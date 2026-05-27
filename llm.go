//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// LLMScorer runs an investigator agent against suspicious syscall events.
//
// Each event triggers a Claude tool-use loop in which the model can call:
//   - get_process_info(pid)
//   - recent_events_for_pid(pid, n)
//   - path_metadata(path)
//
// to gather context before emitting a final structured verdict. This is
// genuine agent engineering — multi-turn decision-making with external
// state — not a single API call.
type LLMScorer struct {
	client    *http.Client
	apiKey    string
	model     string
	queue     chan *Event
	dashboard *Dashboard
	encoder   *json.Encoder
	history   *EventHistory
}

const (
	anthropicEndpoint = "https://api.anthropic.com/v1/messages"
	anthropicVersion  = "2023-06-01"
	defaultModel      = "claude-haiku-4-5"
	llmRequestTimeout = 30 * time.Second
	maxAgentTurns     = 6 // hard ceiling on tool-use rounds
)

func NewLLMScorer(apiKey, model string, dash *Dashboard, hist *EventHistory, queueSize int, stdoutEnc *json.Encoder) *LLMScorer {
	if model == "" {
		model = defaultModel
	}
	return &LLMScorer{
		client:    &http.Client{Timeout: llmRequestTimeout},
		apiKey:    apiKey,
		model:     model,
		queue:     make(chan *Event, queueSize),
		dashboard: dash,
		encoder:   stdoutEnc,
		history:   hist,
	}
}

func (l *LLMScorer) Start(workers int) {
	for i := 0; i < workers; i++ {
		go l.worker()
	}
}

func (l *LLMScorer) Submit(evt Event) bool {
	select {
	case l.queue <- &evt:
		return true
	default:
		return false
	}
}

func (l *LLMScorer) worker() {
	for evt := range l.queue {
		l.investigate(evt)
	}
}

// investigate runs the multi-turn agent loop for one event.
func (l *LLMScorer) investigate(evt *Event) {
	ctx, cancel := context.WithTimeout(context.Background(), llmRequestTimeout)
	defer cancel()

	res, err := l.runAgentLoop(ctx, evt)
	if err != nil {
		log.Printf("llm: agent failed for event id=%d: %v", evt.ID, err)
		return
	}

	out := *evt
	out.Risk = res.Risk
	out.RiskCategory = res.Category
	out.RiskReason = res.Reason

	if l.encoder != nil {
		_ = l.encoder.Encode(out)
	}
	if l.dashboard != nil {
		l.dashboard.Broadcast(&out)
	}
}

// ─── Agent loop ────────────────────────────────────────────────────────

type scoreResult struct {
	Risk     int    `json:"risk"`
	Category string `json:"category"`
	Reason   string `json:"reason"`
}

// runAgentLoop drives a Claude tool-use conversation until the model
// emits its final verdict (a text block containing a JSON object).
func (l *LLMScorer) runAgentLoop(ctx context.Context, evt *Event) (*scoreResult, error) {
	messages := []anthropicMessage{
		{Role: "user", Content: rawContent(buildUserPrompt(evt))},
	}

	for turn := 0; turn < maxAgentTurns; turn++ {
		resp, err := l.callClaude(ctx, messages)
		if err != nil {
			return nil, err
		}

		// Append the assistant's full content block to the conversation
		// so subsequent tool_result messages reference it correctly.
		messages = append(messages, anthropicMessage{
			Role:    "assistant",
			Content: resp.Content,
		})

		switch resp.StopReason {
		case "tool_use":
			toolResults := l.runTools(resp.Content)
			messages = append(messages, anthropicMessage{
				Role:    "user",
				Content: toolResults,
			})
		case "end_turn", "stop_sequence", "max_tokens":
			if v, err := extractVerdict(resp.Content); err == nil {
				return v, nil
			}
			return nil, fmt.Errorf("agent stopped with %q but no parseable verdict", resp.StopReason)
		default:
			return nil, fmt.Errorf("unexpected stop_reason: %q", resp.StopReason)
		}
	}
	return nil, fmt.Errorf("agent exceeded max turns (%d)", maxAgentTurns)
}

// extractVerdict pulls the first valid scoreResult JSON object from
// the model's last text content block.
func extractVerdict(blocks []contentBlock) (*scoreResult, error) {
	for _, b := range blocks {
		if b.Type != "text" {
			continue
		}
		text := strings.TrimSpace(b.Text)
		// Strip optional markdown fences.
		text = strings.TrimPrefix(text, "```json")
		text = strings.TrimPrefix(text, "```")
		text = strings.TrimSuffix(text, "```")
		text = strings.TrimSpace(text)
		// The model may include preamble like "Here's my verdict:\n{...}".
		// Find the first '{' and try to parse from there.
		if i := strings.Index(text, "{"); i >= 0 {
			text = text[i:]
		}
		var sr scoreResult
		if err := json.Unmarshal([]byte(text), &sr); err == nil {
			if sr.Risk < 0 {
				sr.Risk = 0
			}
			if sr.Risk > 100 {
				sr.Risk = 100
			}
			return &sr, nil
		}
	}
	return nil, fmt.Errorf("no verdict block found")
}

// ─── Tools ─────────────────────────────────────────────────────────────

// runTools executes each tool_use block in `blocks` and returns the
// corresponding tool_result content blocks.
func (l *LLMScorer) runTools(blocks []contentBlock) []contentBlock {
	results := []contentBlock{}
	for _, b := range blocks {
		if b.Type != "tool_use" {
			continue
		}
		output := l.dispatchTool(b.Name, b.Input)
		results = append(results, contentBlock{
			Type:      "tool_result",
			ToolUseID: b.ID,
			Content:   output,
		})
	}
	return results
}

func (l *LLMScorer) dispatchTool(name string, input json.RawMessage) string {
	switch name {
	case "get_process_info":
		var args struct {
			PID int `json:"pid"`
		}
		if err := json.Unmarshal(input, &args); err != nil {
			return fmt.Sprintf("error: bad input: %v", err)
		}
		return toolGetProcessInfo(args.PID)

	case "recent_events_for_pid":
		var args struct {
			PID uint32 `json:"pid"`
			N   int    `json:"n"`
		}
		if err := json.Unmarshal(input, &args); err != nil {
			return fmt.Sprintf("error: bad input: %v", err)
		}
		if args.N <= 0 || args.N > 50 {
			args.N = 20
		}
		return toolRecentEvents(l.history, args.PID, args.N)

	case "path_metadata":
		var args struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(input, &args); err != nil {
			return fmt.Sprintf("error: bad input: %v", err)
		}
		return toolPathMetadata(args.Path)

	default:
		return fmt.Sprintf("error: unknown tool %q", name)
	}
}

func toolGetProcessInfo(pid int) string {
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return fmt.Sprintf("process %d not found (may have already exited): %v", pid, err)
	}
	cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	cmd := strings.ReplaceAll(string(cmdline), "\x00", " ")
	cmd = strings.TrimSpace(cmd)

	// Extract the most useful fields from /proc/PID/status.
	var name, parent, uid string
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "Name:"):
			name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		case strings.HasPrefix(line, "PPid:"):
			parent = strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
		case strings.HasPrefix(line, "Uid:"):
			uid = strings.TrimSpace(strings.TrimPrefix(line, "Uid:"))
		}
	}
	return fmt.Sprintf("pid=%d name=%s parent_pid=%s uid=%s cmdline=%q",
		pid, name, parent, uid, cmd)
}

func toolRecentEvents(h *EventHistory, pid uint32, n int) string {
	if h == nil {
		return "error: event history unavailable"
	}
	events := h.RecentForPID(pid, n)
	if len(events) == 0 {
		return fmt.Sprintf("no prior events recorded for pid=%d", pid)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d recent events for pid=%d (newest first):\n", len(events), pid)
	for _, e := range events {
		switch e.Type {
		case "exec", "openat", "unlinkat":
			fmt.Fprintf(&b, "  %s %s path=%q comm=%s\n", e.Time, e.Type, e.Path, e.Comm)
		case "connect":
			fmt.Fprintf(&b, "  %s connect dest=%s family=%s comm=%s\n", e.Time, e.Dest, e.Family, e.Comm)
		case "socket":
			fmt.Fprintf(&b, "  %s socket family=%s type=%s comm=%s\n", e.Time, e.Family, e.SockType, e.Comm)
		default:
			fmt.Fprintf(&b, "  %s %s comm=%s\n", e.Time, e.Type, e.Comm)
		}
	}
	return b.String()
}

func toolPathMetadata(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Sprintf("path %q does not exist", path)
		}
		return fmt.Sprintf("error stat %q: %v", path, err)
	}
	kind := "regular file"
	switch {
	case info.IsDir():
		kind = "directory"
	case info.Mode()&os.ModeSymlink != 0:
		kind = "symlink"
	case info.Mode()&os.ModeDevice != 0:
		kind = "device"
	}
	systemCritical := false
	for _, p := range []string{"/usr/", "/etc/", "/bin/", "/sbin/", "/lib/", "/boot/"} {
		if strings.HasPrefix(path, p) {
			systemCritical = true
			break
		}
	}
	return fmt.Sprintf("path=%q kind=%s size=%d mode=%s system_critical=%t",
		path, kind, info.Size(), info.Mode(), systemCritical)
}

// ─── Anthropic API types ───────────────────────────────────────────────

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system"`
	Messages  []anthropicMessage `json:"messages"`
	Tools     []toolDef          `json:"tools,omitempty"`
}

type anthropicMessage struct {
	Role    string         `json:"role"`
	Content []contentBlock `json:"content"`
}

// contentBlock covers every block kind we send or receive: text,
// tool_use (from assistant), tool_result (from user).
type contentBlock struct {
	Type string `json:"type"`

	// type=text
	Text string `json:"text,omitempty"`

	// type=tool_use
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`

	// type=tool_result
	ToolUseID string `json:"tool_use_id,omitempty"`
	Content   string `json:"content,omitempty"`
}

type toolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

type anthropicResponse struct {
	Content    []contentBlock `json:"content"`
	StopReason string         `json:"stop_reason"`
	Error      *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func rawContent(text string) []contentBlock {
	return []contentBlock{{Type: "text", Text: text}}
}

func (l *LLMScorer) callClaude(ctx context.Context, messages []anthropicMessage) (*anthropicResponse, error) {
	reqBody := anthropicRequest{
		Model:     l.model,
		MaxTokens: 1024,
		System:    systemPrompt,
		Messages:  messages,
		Tools:     allTools,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", anthropicEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-api-key", l.apiKey)
	req.Header.Set("anthropic-version", anthropicVersion)
	req.Header.Set("content-type", "application/json")

	resp, err := l.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api %d: %s", resp.StatusCode, truncate(string(respBody), 300))
	}

	var ar anthropicResponse
	if err := json.Unmarshal(respBody, &ar); err != nil {
		return nil, fmt.Errorf("decode: %w (body: %s)", err, truncate(string(respBody), 200))
	}
	if ar.Error != nil {
		return nil, fmt.Errorf("api error %s: %s", ar.Error.Type, ar.Error.Message)
	}
	return &ar, nil
}

// ─── Tool definitions sent in every request ────────────────────────────

var allTools = []toolDef{
	{
		Name:        "get_process_info",
		Description: "Look up live metadata for a running process by PID: command name, parent PID, UID, and full command line. Returns an error if the process has already exited.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"pid": map[string]any{
					"type":        "integer",
					"description": "Process ID to look up",
				},
			},
			"required": []string{"pid"},
		},
	},
	{
		Name:        "recent_events_for_pid",
		Description: "Fetch up to N most recent syscall events recorded for a given PID, newest first. Useful to see what else this process has been doing leading up to the alert.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"pid": map[string]any{
					"type":        "integer",
					"description": "Process ID",
				},
				"n": map[string]any{
					"type":        "integer",
					"description": "Maximum events to return (1-50)",
				},
			},
			"required": []string{"pid"},
		},
	},
	{
		Name:        "path_metadata",
		Description: "Stat a filesystem path: file type (regular file / directory / symlink), size, permission bits, and whether the path is under a system-critical directory (/usr, /etc, /bin, /sbin, /lib, /boot).",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{
					"type":        "string",
					"description": "Absolute path to inspect",
				},
			},
			"required": []string{"path"},
		},
	},
}

// ─── Prompts ───────────────────────────────────────────────────────────

const systemPrompt = `You are a runtime-security investigator agent. For each syscall event observed from an AI agent process, you must produce a structured risk assessment.

You have access to three tools to gather context before deciding:
  - get_process_info(pid)            — live process metadata
  - recent_events_for_pid(pid, n)    — this process's recent syscall history
  - path_metadata(path)              — file/directory metadata

Reasoning approach:
  1. If the event is obviously benign (e.g. exec of /usr/bin/ls by a normal user), you may skip tool calls and verdict immediately.
  2. If the event involves a destructive or sensitive operation, use one or more tools to check parent process, recent history, and target metadata BEFORE deciding risk.
  3. Be skeptical: a single bad-looking event in a long history of normal ones may be a false positive; conversely, a benign-looking event amid a cleanup-then-exfiltrate pattern is very serious.

When you have enough information, output ONLY a JSON object of this shape (no markdown fences, no preamble):

{
  "risk": <integer 0-100>,
  "category": "destructive" | "exfiltration" | "recon" | "egress" | "benign",
  "reason": "<one or two sentences, citing concrete evidence you gathered>"
}

Reserve risk ≥ 80 for actions that would cause irreversible damage or clear policy violation.`

func buildUserPrompt(evt *Event) string {
	parts := []string{
		fmt.Sprintf(`process %q pid=%d uid=%d %s`, evt.Comm, evt.PID, evt.UID, evt.Type),
	}
	if evt.Path != "" {
		parts = append(parts, fmt.Sprintf(`path=%q`, evt.Path))
	}
	if evt.Dest != "" {
		parts = append(parts, fmt.Sprintf(`dest=%s`, evt.Dest))
	}
	if evt.Family != "" {
		parts = append(parts, fmt.Sprintf(`family=%s`, evt.Family))
	}
	if evt.SockType != "" {
		parts = append(parts, fmt.Sprintf(`socktype=%s`, evt.SockType))
	}
	if evt.Rule != "" {
		parts = append(parts, fmt.Sprintf(`(matched rule %q action=%s severity=%s)`,
			evt.Rule, evt.Action, evt.Severity))
	}
	return "Investigate this event: " + strings.Join(parts, " ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
