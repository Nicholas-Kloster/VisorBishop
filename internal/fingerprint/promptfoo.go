package fingerprint

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Nicholas-Kloster/VisorBishop/internal/probe"
)

// PromptfooProber detects promptfoo self-hosted server instances.
//
// promptfoo is an LLM evaluation framework. The web UI (`promptfoo view`)
// runs a Node.js server, typically on port 3000, that serves eval
// results to a Next.js dashboard. /api/results/ returns the eval list.
// Authentication is NOT enabled by default in the OSS server — operators
// who expose port 3000 publicly leak their full eval history including
// prompts, model responses, and assertion failures.
//
// Reference: github.com/promptfoo/promptfoo
type PromptfooProber struct{}

func (p PromptfooProber) ID() Platform { return Promptfoo }

func (p PromptfooProber) Probe(ctx context.Context, client *http.Client, target, hostname string) Finding {
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: Promptfoo,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}

	// Note the trailing slash — promptfoo's Next.js routes require it.
	// Use a generous 64KB read budget since the eval list can be large.
	r := probe.Get(ctx, client, target+"/api/results/", hostname, 65536)
	f.LatencyMS = r.LatencyMS
	if r.Err != nil {
		return f
	}

	indicators := map[string]interface{}{}

	switch {
	case r.Status == 200:
		// First try a strict full-parse; fall back to a "starts with the
		// expected shape" heuristic when the body is truncated.
		bodyStr := string(r.Body)
		var results struct {
			Data []struct {
				EvalID      string `json:"evalId"`
				Description string `json:"description"`
				NumTests    int    `json:"numTests"`
			} `json:"data"`
		}
		strictParse := json.Unmarshal(r.Body, &results) == nil && results.Data != nil
		looseMatch := strings.HasPrefix(bodyStr, `{"data":[{"evalId":`) ||
			strings.HasPrefix(bodyStr, `{"data":[]}`)

		if strictParse || looseMatch {
			f.Confirmed = true
			f.Auth = AuthOpen
			f.Severity = SevCritical
			if strictParse {
				indicators["eval_count"] = len(results.Data)
			}
			f.Notes = append(f.Notes, "CRITICAL: /api/results/ returns eval history without authentication")
		}
	case r.Status == 401 || r.Status == 403:
		// Promptfoo with auth-fronting (unusual)
		f.Confirmed = true
		f.Auth = AuthProtected
		f.Severity = SevInfo
	default:
		// Try the SPA fallback
		rr := probe.Get(ctx, client, target+"/", hostname, 4096)
		body := string(rr.Body)
		if rr.Status == 200 && (containsPromptfoo(body)) {
			f.Confirmed = true
			f.Auth = AuthUnknown
			f.Severity = SevInfo
		}
	}

	if f.Confirmed && len(indicators) > 0 {
		f.Indicators = indicators
	}
	return f
}

func containsPromptfoo(body string) bool {
	for _, marker := range []string{
		"promptfoo",
		"<title>promptfoo</title>",
		"/_next/static/chunks/promptfoo",
	} {
		if idx := indexOfFold(body, marker); idx >= 0 {
			return true
		}
	}
	return false
}

// indexOfFold is a case-insensitive substring search.
func indexOfFold(s, substr string) int {
	if substr == "" {
		return 0
	}
	if len(s) < len(substr) {
		return -1
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			c1, c2 := s[i+j], substr[j]
			if c1 >= 'A' && c1 <= 'Z' {
				c1 += 32
			}
			if c2 >= 'A' && c2 <= 'Z' {
				c2 += 32
			}
			if c1 != c2 {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
