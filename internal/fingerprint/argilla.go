package fingerprint

import (
	"context"
	"net/http"
	"strings"

	"github.com/Nicholas-Kloster/VisorBishop/internal/probe"
)

// ArgillaProber detects Argilla data-annotation server instances.
//
// Argilla is HuggingFace's open-source data annotation platform for LLM
// training datasets. The server defaults to mandatory API-key auth on
// every protected endpoint (/api/v1/me, /api/v1/datasets, etc.). The
// confirmation signal is the response shape on /api/v1/me:
//
//   {"detail":{"code":"argilla.api.errors::UnauthorizedError",...}}
//
// Reference: github.com/argilla-io/argilla
type ArgillaProber struct{}

func (p ArgillaProber) ID() Platform { return Argilla }

func (p ArgillaProber) Probe(ctx context.Context, client *http.Client, target, hostname string) Finding {
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: Argilla,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}

	r := probe.Get(ctx, client, target+"/api/v1/me", hostname, 1024)
	f.LatencyMS = r.LatencyMS
	if r.Err != nil {
		return f
	}
	body := string(r.Body)

	// The Argilla error shape is the strongest signal
	if strings.Contains(body, "argilla.api.errors::UnauthorizedError") {
		f.Confirmed = true
		f.Auth = AuthProtected
		f.Severity = SevInfo
	} else if r.Status == 200 && strings.Contains(body, `"username"`) {
		// Returning user info on /me without auth = misconfigured anonymous access
		f.Confirmed = true
		f.Auth = AuthOpen
		f.Severity = SevCritical
		f.Notes = append(f.Notes, "CRITICAL: /api/v1/me returns user info without auth")
	} else {
		// Try title-fallback for SPA hosts where /api/v1/me redirects
		rr := probe.Get(ctx, client, target+"/", hostname, 4096)
		if strings.Contains(string(rr.Body), "Argilla") && strings.Contains(string(rr.Body), "<title>") {
			// Confirmed via SPA but auth state unknown
			f.Confirmed = true
			f.Auth = AuthUnknown
			f.Severity = SevInfo
		}
	}
	return f
}
