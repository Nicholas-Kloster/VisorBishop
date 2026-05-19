// VisorBishop — meta-fingerprinter for the AI observability tier.
//
// Walks a list of HTTP(S) targets, identifies which observability platform
// each one runs (Phoenix, Langfuse, Helicone, LangSmith, Lunary, OpenLIT,
// Pezzo), captures version + auth-posture signals, and optionally probes the
// host IP for co-located unauth services (the IP-direct-shadow methodology).
//
// Read-only by design. No credential testing, no payload fuzzing.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Nicholas-Kloster/VisorBishop/internal/fingerprint"
	"github.com/Nicholas-Kloster/VisorBishop/internal/output"
	"github.com/Nicholas-Kloster/VisorBishop/internal/probe"
)

const Version = "0.1.7"

func main() {
	var (
		inputFile   = flag.String("i", "", "Input file with one URL per line (or - for stdin)")
		target      = flag.String("t", "", "Single target URL (alternative to -i)")
		concurrency = flag.Int("c", 16, "Concurrent probes")
		timeout     = flag.Duration("timeout", 8*time.Second, "Per-probe timeout")
		ipShadow    = flag.Bool("ip-shadow", false, "Also run the IP-direct-shadow port sweep on each confirmed platform IP")
		ipShadowAll = flag.Bool("ip-shadow-all", false, "Run IP-shadow on every target, even non-platform-confirmed ones")
		jsonOut     = flag.String("json", "", "Write JSON report to this file")
		csvOut      = flag.String("csv", "", "Write CSV summary to this file")
		quiet       = flag.Bool("q", false, "Suppress per-target progress lines")
		showVer     = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("VisorBishop", Version)
		return
	}

	if *inputFile == "" && *target == "" {
		fmt.Fprintln(os.Stderr, "VisorBishop: provide -i <file> or -t <url>")
		flag.Usage()
		os.Exit(2)
	}

	targets, err := loadTargets(*inputFile, *target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "VisorBishop: load targets:", err)
		os.Exit(1)
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "VisorBishop: no targets")
		os.Exit(1)
	}

	probers := []fingerprint.Prober{
		fingerprint.OpenWebUIProber{},
		fingerprint.LiteLLMProber{},
		fingerprint.PhoenixProber{},
		fingerprint.LangSmithProber{},
		fingerprint.LangfuseProber{},
		fingerprint.HeliconeProber{},
		fingerprint.OpikProber{},
		fingerprint.AgentOpsProber{},
		fingerprint.ArgillaProber{},
		fingerprint.PromptfooProber{},
		fingerprint.OpenLITProber{},
		fingerprint.LunaryProber{},
		fingerprint.PezzoProber{},
		fingerprint.MLflowProber{},
		fingerprint.WandbProber{},
		fingerprint.LangflowProber{},
		fingerprint.DifyProber{},
		fingerprint.KubeflowProber{},
		fingerprint.PostHogProber{},
		fingerprint.PrefectProber{},
		fingerprint.AirflowProber{},
	}

	if !*quiet {
		fmt.Fprintf(os.Stderr, "VisorBishop %s — %d targets, concurrency=%d, timeout=%s\n",
			Version, len(targets), *concurrency, *timeout)
		if *ipShadow || *ipShadowAll {
			fmt.Fprintf(os.Stderr, "IP-direct-shadow enabled (%d ports per host)\n", len(probe.ShadowPorts))
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := probe.NewClient(*timeout)
	reports := make([]output.HostReport, len(targets))

	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t targetRef) {
			defer wg.Done()
			defer func() { <-sem }()
			reports[i] = probeTarget(ctx, client, t, probers, *timeout, *ipShadow, *ipShadowAll)
			if !*quiet && reports[i].Platform.Confirmed {
				sev := reports[i].Platform.Severity
				fmt.Fprintf(os.Stderr, "  [%s] %s — %s v%s\n",
					string(sev), t.URL, reports[i].Platform.Platform, reports[i].Platform.Version)
			}
		}(i, t)
	}
	wg.Wait()

	output.SortReports(reports)

	if *jsonOut != "" {
		f, err := os.Create(*jsonOut)
		if err != nil {
			fmt.Fprintln(os.Stderr, "VisorBishop: open JSON output:", err)
			os.Exit(1)
		}
		output.WriteJSON(f, reports)
		f.Close()
		if !*quiet {
			fmt.Fprintf(os.Stderr, "JSON report → %s\n", *jsonOut)
		}
	}

	if *csvOut != "" {
		f, err := os.Create(*csvOut)
		if err != nil {
			fmt.Fprintln(os.Stderr, "VisorBishop: open CSV output:", err)
			os.Exit(1)
		}
		output.WriteCSV(f, reports)
		f.Close()
		if !*quiet {
			fmt.Fprintf(os.Stderr, "CSV summary → %s\n", *csvOut)
		}
	}

	output.WriteText(os.Stdout, reports)
}

type targetRef struct {
	URL      string
	Hostname string
}

func loadTargets(file, single string) ([]targetRef, error) {
	if single != "" {
		return []targetRef{parseTargetLine(single)}, nil
	}

	var r *os.File
	if file == "-" {
		r = os.Stdin
	} else {
		var err error
		r, err = os.Open(file)
		if err != nil {
			return nil, err
		}
		defer r.Close()
	}

	var targets []targetRef
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, parseTargetLine(line))
	}
	return targets, scanner.Err()
}

// parseTargetLine accepts several formats:
//   "https://1.2.3.4:443"                           full URL
//   "https://1.2.3.4:443\thostname.example.com"     URL + hostname (TSV)
//   "1.2.3.4:443"                                   bare IP:port (scheme inferred: 443→https, else http)
//   "1.2.3.4:443\thostname.example.com"             bare + hostname
func parseTargetLine(line string) targetRef {
	parts := strings.SplitN(line, "\t", 2)
	url := strings.TrimSpace(parts[0])
	// If no scheme, infer from port
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		// Extract port (last colon)
		port := "80"
		if i := strings.LastIndex(url, ":"); i > 0 {
			candidate := url[i+1:]
			// Sanity-check it's numeric
			allDigits := candidate != ""
			for _, c := range candidate {
				if c < '0' || c > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				port = candidate
			}
		}
		scheme := "http"
		if port == "443" || port == "8443" || port == "9443" {
			scheme = "https"
		}
		url = scheme + "://" + url
	}
	t := targetRef{URL: url}
	if len(parts) > 1 {
		t.Hostname = strings.TrimSpace(parts[1])
	}
	return t
}

func probeTarget(ctx context.Context, client interface{}, t targetRef, probers []fingerprint.Prober, timeout time.Duration, ipShadow, ipShadowAll bool) output.HostReport {
	r := output.HostReport{Target: t.URL}

	// Probe each platform until one confirms
	httpClient := probe.NewClient(timeout)
	for _, p := range probers {
		pctx, cancel := context.WithTimeout(ctx, timeout*3)
		f := p.Probe(pctx, httpClient, t.URL, t.Hostname)
		cancel()
		if f.Confirmed {
			r.Platform = f
			break
		}
	}

	// If nothing matched, store an unconfirmed placeholder
	if !r.Platform.Confirmed {
		r.Platform = fingerprint.Finding{
			Target:   t.URL,
			Hostname: t.Hostname,
			Auth:     fingerprint.AuthUnknown,
			Severity: fingerprint.SevNone,
		}
	}

	// IP-shadow probe if requested
	if ipShadow && r.Platform.Confirmed {
		ip := probe.ExtractIP(t.URL)
		if isLikelyIP(ip) {
			r.ShadowFindings = probe.ShadowScan(ctx, ip, timeout)
			// Bump severity if shadow surfaces an unauth service
			for _, s := range r.ShadowFindings {
				if s.Unauth {
					if output.SeverityRank(r.Platform.Severity) < output.SeverityRank(fingerprint.SevHigh) {
						r.Platform.Severity = fingerprint.SevHigh
					}
					r.Platform.Notes = append(r.Platform.Notes,
						fmt.Sprintf("IP-shadow: unauth %s on :%d", s.Service, s.Port))
				}
			}
		}
	} else if ipShadowAll {
		ip := probe.ExtractIP(t.URL)
		if isLikelyIP(ip) {
			r.ShadowFindings = probe.ShadowScan(ctx, ip, timeout)
		}
	}

	return r
}

func isLikelyIP(s string) bool {
	if s == "" {
		return false
	}
	// Trivial check: at least one dot, all parts numeric
	dots := 0
	for _, c := range s {
		if c == '.' {
			dots++
		} else if !(c >= '0' && c <= '9') {
			return false
		}
	}
	return dots == 3
}
