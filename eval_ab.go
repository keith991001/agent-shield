//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

// PromptVariant is one entry in evals/prompts.yaml — a labelled system
// prompt to be benchmarked against the scenario corpus.
type PromptVariant struct {
	ID           string `yaml:"id"`
	Description  string `yaml:"description"`
	SystemPrompt string `yaml:"system_prompt"`
}

type promptVariantFile struct {
	Variants []PromptVariant `yaml:"variants"`
}

// LoadPromptVariants reads the YAML and returns the variant list.
// An empty system_prompt is allowed and means "use the built-in default".
func LoadPromptVariants(path string) ([]PromptVariant, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read prompts file: %w", err)
	}
	var f promptVariantFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse prompts: %w", err)
	}
	for i := range f.Variants {
		if f.Variants[i].ID == "" {
			return nil, fmt.Errorf("variant %d has empty id", i)
		}
	}
	return f.Variants, nil
}

// VariantSummary aggregates one variant's results across the scenarios.
type VariantSummary struct {
	Variant      PromptVariant
	Passed       int
	Total        int
	AvgTurns     float64
	AvgToolCalls float64
	ParallelUses int
	Reflections  int
	Revisions    int
	TotalCostUSD float64
	AvgLatency   time.Duration
	Failures     []string // scenario IDs that failed
}

// RunABEval runs every prompt variant against the full scenario list,
// reusing one LLMScorer per variant (so cache / state aren't shared
// across variants).
func RunABEval(
	ctx context.Context,
	makeScorer func(systemPrompt string) *LLMScorer, // factory so each variant gets a clean scorer
	hist *EventHistory,
	variants []PromptVariant,
	scenarios []Scenario,
) []VariantSummary {
	summaries := make([]VariantSummary, 0, len(variants))

	for vi, v := range variants {
		fmt.Printf("\n▶ Variant %d/%d: %s\n", vi+1, len(variants), v.ID)
		if v.Description != "" {
			fmt.Printf("  %s\n", v.Description)
		}
		fmt.Println()

		scorer := makeScorer(v.SystemPrompt)

		results := RunEvals(ctx, scorer, hist, scenarios)
		s := aggregateVariant(v, results)
		summaries = append(summaries, s)
	}

	printABComparison(summaries)
	return summaries
}

func aggregateVariant(v PromptVariant, results []EvalResult) VariantSummary {
	s := VariantSummary{Variant: v, Total: len(results)}
	var totLat time.Duration
	denomLat := 0
	for _, r := range results {
		if r.Passed {
			s.Passed++
		} else {
			s.Failures = append(s.Failures, r.ID)
		}
		if r.Err != nil {
			continue
		}
		totLat += r.Latency
		denomLat++
		if r.Trace == nil {
			continue
		}
		s.AvgTurns += float64(r.Trace.Turns)
		s.AvgToolCalls += float64(r.Trace.TotalToolCalls)
		if r.Trace.MaxParallelTools > 1 {
			s.ParallelUses++
		}
		if r.Trace.Reflected {
			s.Reflections++
		}
		if r.Trace.VerdictRevised {
			s.Revisions++
		}
		s.TotalCostUSD += r.Trace.EstimateCostUSD()
	}
	if denomLat > 0 {
		s.AvgTurns /= float64(denomLat)
		s.AvgToolCalls /= float64(denomLat)
		s.AvgLatency = totLat / time.Duration(denomLat)
	}
	return s
}

func printABComparison(summaries []VariantSummary) {
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════════════")
	fmt.Println("  A/B COMPARISON")
	fmt.Println("═══════════════════════════════════════════════════════════════════════")

	// Header
	fmt.Printf("  %-24s %-8s %-9s %-9s %-7s %-8s %-7s\n",
		"variant", "pass", "avg_turns", "avg_tools", "parallel", "cost", "fails")
	fmt.Println("  ─────────────────────────────────────────────────────────────────────")
	for _, s := range summaries {
		pct := 0.0
		if s.Total > 0 {
			pct = 100 * float64(s.Passed) / float64(s.Total)
		}
		fmt.Printf("  %-24s %-8s %-9s %-9s %-7s %-8s %-7d\n",
			truncateID(s.Variant.ID, 24),
			fmt.Sprintf("%d/%d (%.0f%%)", s.Passed, s.Total, pct),
			fmt.Sprintf("%.2f", s.AvgTurns),
			fmt.Sprintf("%.2f", s.AvgToolCalls),
			fmt.Sprintf("%d/%d", s.ParallelUses, s.Total),
			fmt.Sprintf("$%.4f", s.TotalCostUSD),
			len(s.Failures),
		)
	}

	// Best-by metrics
	bestPass := pickBest(summaries, func(s VariantSummary) float64 {
		return float64(s.Passed) / float64(maxInt(s.Total, 1))
	})
	bestCost := pickBestLower(summaries, func(s VariantSummary) float64 {
		if s.Passed == 0 {
			return 1e9 // disqualify
		}
		return s.TotalCostUSD / float64(s.Passed)
	})
	bestLatency := pickBestLower(summaries, func(s VariantSummary) float64 {
		return float64(s.AvgLatency)
	})

	fmt.Println()
	fmt.Printf("  Best by pass rate:   %s\n", bestPass.Variant.ID)
	fmt.Printf("  Best $/pass:         %s ($%.4f / pass)\n",
		bestCost.Variant.ID,
		bestCost.TotalCostUSD/float64(maxInt(bestCost.Passed, 1)))
	fmt.Printf("  Best by latency:     %s (avg %s)\n",
		bestLatency.Variant.ID, bestLatency.AvgLatency.Round(time.Millisecond))
}

func truncateID(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func pickBest(items []VariantSummary, score func(VariantSummary) float64) VariantSummary {
	sort.SliceStable(items, func(i, j int) bool { return score(items[i]) > score(items[j]) })
	return items[0]
}

func pickBestLower(items []VariantSummary, score func(VariantSummary) float64) VariantSummary {
	sort.SliceStable(items, func(i, j int) bool { return score(items[i]) < score(items[j]) })
	return items[0]
}
