//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Scenario is one entry in evals/scenarios.yaml: a syscall event we want
// the investigator agent to classify, plus the expected verdict range.
type Scenario struct {
	ID          string      `yaml:"id"`
	Description string      `yaml:"description"`
	History     []Event     `yaml:"history,omitempty"` // optional seed for EventHistory
	Event       Event       `yaml:"event"`
	Expected    Expectation `yaml:"expected"`
}

// Expectation defines the verdict range a scenario passes within.
// Risk is treated as an interval since LLM outputs are probabilistic.
type Expectation struct {
	RiskMin  int    `yaml:"risk_min"`
	RiskMax  int    `yaml:"risk_max"`
	Category string `yaml:"category"`
}

type scenarioFile struct {
	Scenarios []Scenario `yaml:"scenarios"`
}

// LoadEvalScenarios parses the YAML file into a Scenario slice.
func LoadEvalScenarios(path string) ([]Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read scenarios: %w", err)
	}
	var f scenarioFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse scenarios: %w", err)
	}
	return f.Scenarios, nil
}

// EvalResult records the outcome of one scenario.
type EvalResult struct {
	ID       string
	Expected Expectation
	Verdict  *scoreResult
	Latency  time.Duration
	Err      error
	Passed   bool
	Reason   string // why it passed or failed
}

// RunEvals executes each scenario sequentially. Sequential keeps the
// rate well below API limits and makes output easy to follow.
func RunEvals(ctx context.Context, llm *LLMScorer, hist *EventHistory, scenarios []Scenario) []EvalResult {
	results := make([]EvalResult, 0, len(scenarios))
	width := 0
	for _, s := range scenarios {
		if len(s.ID) > width {
			width = len(s.ID)
		}
	}

	fmt.Printf("Running %d scenarios (model=%s)\n\n", len(scenarios), llm.model)

	for i, sc := range scenarios {
		// Seed history with prior events for this scenario, if any.
		for _, e := range sc.History {
			hist.Add(e)
		}

		fmt.Printf("  [%2d/%d] %-*s  ", i+1, len(scenarios), width, sc.ID)

		start := time.Now()
		verdict, err := llm.runAgentLoop(ctx, &sc.Event)
		latency := time.Since(start)

		r := EvalResult{
			ID:       sc.ID,
			Expected: sc.Expected,
			Verdict:  verdict,
			Latency:  latency,
			Err:      err,
		}

		if err != nil {
			r.Passed = false
			r.Reason = fmt.Sprintf("agent error: %v", err)
			fmt.Printf("ERROR  %s\n", r.Reason)
		} else {
			r.Passed, r.Reason = checkVerdict(verdict, &sc.Expected)
			symbol := "✓ PASS"
			if !r.Passed {
				symbol = "✗ FAIL"
			}
			fmt.Printf("%s  risk=%-3d cat=%-13s %4.1fs",
				symbol, verdict.Risk, verdict.Category, latency.Seconds())
			if !r.Passed {
				fmt.Printf("  %s", r.Reason)
			}
			fmt.Println()
		}

		results = append(results, r)
	}
	return results
}

func checkVerdict(v *scoreResult, e *Expectation) (bool, string) {
	if v.Risk < e.RiskMin || v.Risk > e.RiskMax {
		return false, fmt.Sprintf("risk %d outside [%d, %d]", v.Risk, e.RiskMin, e.RiskMax)
	}
	if e.Category != "" && v.Category != e.Category {
		return false, fmt.Sprintf("category %q ≠ expected %q", v.Category, e.Category)
	}
	return true, ""
}

// PrintEvalSummary prints aggregate metrics: pass rate, by-category
// accuracy, average latency.
func PrintEvalSummary(results []EvalResult) {
	total := len(results)
	if total == 0 {
		return
	}

	passed := 0
	errored := 0
	var totalLatency time.Duration
	type bucket struct{ pass, total int }
	byCat := map[string]*bucket{}

	for _, r := range results {
		if r.Err != nil {
			errored++
			continue
		}
		totalLatency += r.Latency
		if r.Passed {
			passed++
		}
		cat := r.Expected.Category
		if cat == "" {
			cat = "(any)"
		}
		b := byCat[cat]
		if b == nil {
			b = &bucket{}
			byCat[cat] = b
		}
		b.total++
		if r.Passed {
			b.pass++
		}
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  SUMMARY")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Printf("  Scenarios:       %d\n", total)
	fmt.Printf("  Passed:          %d  (%.1f%%)\n", passed, 100*float64(passed)/float64(total))
	if total-passed-errored > 0 {
		fmt.Printf("  Failed:          %d\n", total-passed-errored)
	}
	if errored > 0 {
		fmt.Printf("  Errored:         %d\n", errored)
	}

	if len(byCat) > 0 {
		fmt.Println()
		fmt.Println("  By expected category:")
		for cat, b := range byCat {
			pct := 100 * float64(b.pass) / float64(b.total)
			fmt.Printf("    %-14s : %d/%d  (%.0f%%)\n", cat, b.pass, b.total, pct)
		}
	}

	if total-errored > 0 {
		avgLatency := totalLatency / time.Duration(total-errored)
		fmt.Println()
		fmt.Printf("  Average latency: %s\n", avgLatency.Round(time.Millisecond))
	}

	// List failing cases compactly.
	failing := []EvalResult{}
	for _, r := range results {
		if !r.Passed {
			failing = append(failing, r)
		}
	}
	if len(failing) > 0 {
		fmt.Println()
		fmt.Println("  Failures:")
		for _, r := range failing {
			fmt.Printf("    %s  →  %s\n", r.ID, r.Reason)
		}
	}
}

// EvalsAllPassed returns true if every scenario passed.
func EvalsAllPassed(results []EvalResult) bool {
	for _, r := range results {
		if !r.Passed {
			return false
		}
	}
	return true
}
