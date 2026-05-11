package probe

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ShadowPort is a port we probe for the IP-direct-shadow methodology.
type ShadowPort struct {
	Port     int
	Service  string
	HTTPPath string // probe path if HTTP; empty for TCP-only banner
}

// ShadowPorts are the cross-cutting ports VisorBishop probes on every
// identified observability platform IP, per Methodology Insight #12.
//
// Phase 2 added the database/cache ports that surfaced ClickHouse and
// Postgres exposures on Helicone's benchmarkit.solutions and Langfuse's
// langfuse.revdot.ai respectively.
//
// Iter-2 (2026-05-11) added the message-broker and object-store ports
// that the AI observability stack commonly co-locates: Kafka (9092),
// RabbitMQ (5672), NATS (4222), Memcached (11211), Logstash (5044),
// and MinIO API (9000). The NATS choice is grounded in the 2026-05-09
// ParamWallet finding (open NATS JetStream ledger + AI pipeline).
//
// Iter-3 (2026-05-11) adds the AI-stack ML pipeline ports — MLflow UI
// (5000), Streamlit (8501), Gradio (7860), Qdrant (6333), Milvus
// (19530), and ChromaDB v1/v2 (8000). These ports are aligned with
// the operator class we're surveying (people running AI observability
// platforms are likely also running adjacent AI tooling on the same
// hosts).
var ShadowPorts = []ShadowPort{
	{111, "rpcbind", ""},
	{1080, "mailcatcher", "/"},
	{2049, "nfs", ""},
	{3306, "mysql", ""},
	{4222, "nats", ""},
	{5000, "mlflow", "/api/2.0/mlflow/experiments/list"},
	{5044, "logstash", ""},
	{5432, "postgresql", ""},
	{5601, "kibana", "/api/status"},
	{5672, "rabbitmq", ""},
	{6333, "qdrant", "/collections"},
	{6379, "redis", ""},
	{7860, "gradio", "/config"},
	{8000, "chromadb", "/api/v1/heartbeat"},
	{8025, "mailhog", "/api/v2/messages?limit=0"},
	{8086, "influxdb", "/ping"},
	{8123, "clickhouse", "/ping"},
	{8501, "streamlit", "/healthz"},
	{9000, "minio_api", "/minio/health/live"},
	{9090, "prometheus", "/api/v1/query?query=up"},
	{9092, "kafka", ""},
	{9093, "alertmanager", "/-/healthy"},
	{9100, "node_exporter", "/metrics"},
	{9200, "elasticsearch", "/"},
	{11211, "memcached", ""},
	{19530, "milvus", ""},
	{27017, "mongodb", ""},
}

// ShadowFinding is one IP-direct-shadow result for a single port.
type ShadowFinding struct {
	IP          string `json:"ip"`
	Port        int    `json:"port"`
	Service     string `json:"service"`
	Open        bool   `json:"open"`
	Confirmed   string `json:"confirmed,omitempty"` // what we actually saw (e.g. "ClickHouse 25.6.13.41")
	Unauth      bool   `json:"unauth,omitempty"`     // true if the service answers without auth
	Banner      string `json:"banner,omitempty"`     // raw banner truncated to 200B
	Notes       []string `json:"notes,omitempty"`
}

// ShadowScan runs the IP-direct-shadow port sweep for one IP, probing all
// 15 ports concurrently. Returns one ShadowFinding per port that was open
// + meaningfully probed.
func ShadowScan(ctx context.Context, ip string, timeout time.Duration) []ShadowFinding {
	results := make([]ShadowFinding, len(ShadowPorts))
	var wg sync.WaitGroup
	for i, sp := range ShadowPorts {
		wg.Add(1)
		go func(i int, sp ShadowPort) {
			defer wg.Done()
			results[i] = scanOnePort(ctx, ip, sp, timeout)
		}(i, sp)
	}
	wg.Wait()
	findings := []ShadowFinding{}
	for _, f := range results {
		if f.Open {
			findings = append(findings, f)
		}
	}
	return findings
}

func scanOnePort(ctx context.Context, ip string, sp ShadowPort, timeout time.Duration) ShadowFinding {
	f := ShadowFinding{
		IP:      ip,
		Port:    sp.Port,
		Service: sp.Service,
	}

	addr := fmt.Sprintf("%s:%d", ip, sp.Port)
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return f
	}
	conn.Close()
	f.Open = true

	// If HTTPPath is set, do an HTTP follow-up to characterize the service
	if sp.HTTPPath != "" {
		f = httpCharacterize(ctx, ip, sp, f, timeout)
	} else if sp.Port == 5432 {
		f.Notes = []string{"PostgreSQL port open; password unknown (no credential test)"}
	} else if sp.Port == 6379 {
		f = redisCharacterize(ctx, ip, sp, f, timeout)
	} else if sp.Port == 2049 {
		f.Notes = []string{"NFS port open; run `showmount -e " + ip + "` to enumerate exports"}
	} else if sp.Port == 4222 {
		f = natsCharacterize(ctx, ip, sp, f, timeout)
	} else if sp.Port == 11211 {
		f = memcachedCharacterize(ctx, ip, sp, f, timeout)
	} else if sp.Port == 9092 {
		f.Notes = []string{"Kafka port open; broker-protocol probe omitted (no credential test)"}
	} else if sp.Port == 5672 {
		f.Notes = []string{"RabbitMQ AMQP port open; credentials unknown (no credential test)"}
	} else if sp.Port == 5044 {
		f.Notes = []string{"Logstash beats-input port open; no client cert/auth test"}
	} else if sp.Port == 19530 {
		f.Notes = []string{"Milvus vector DB gRPC port open; protocol probe omitted"}
	}

	return f
}

func httpCharacterize(ctx context.Context, ip string, sp ShadowPort, f ShadowFinding, timeout time.Duration) ShadowFinding {
	client := NewClient(timeout)
	target := fmt.Sprintf("http://%s:%d%s", ip, sp.Port, sp.HTTPPath)
	r := Get(ctx, client, target, "", 1024)
	if r.Err != nil {
		return f
	}
	body := string(r.Body)
	bodyTrimmed := body
	if len(bodyTrimmed) > 200 {
		bodyTrimmed = bodyTrimmed[:200]
	}
	f.Banner = bodyTrimmed

	switch sp.Service {
	case "prometheus":
		// /api/v1/query returning {"status":"success"} = unauth Prometheus
		if r.Status == 200 && strings.Contains(body, `"status":"success"`) {
			f.Unauth = true
			f.Confirmed = "Prometheus (unauth)"
			f.Notes = append(f.Notes, "/-/quit and /-/reload likely also reachable (DoS primitive)")
		}
	case "kibana":
		// /api/status returning JSON with version = unauth Kibana
		if r.Status == 200 && strings.Contains(body, `"version"`) && strings.Contains(body, `"build_hash"`) {
			f.Unauth = true
			f.Confirmed = "Kibana (unauth)"
		}
	case "mailhog":
		// /api/v2/messages returning {"total":N} = unauth Mailhog
		if r.Status == 200 && strings.Contains(body, `"total":`) {
			f.Unauth = true
			f.Confirmed = "MailHog (unauth)"
			if strings.Contains(body, `"total":0`) {
				f.Notes = append(f.Notes, "MailHog store currently empty (latent capture if app routes mail here)")
			} else {
				f.Notes = append(f.Notes, "ACTUALIZED: MailHog store has messages")
			}
		}
	case "mailcatcher":
		// MailCatcher returns its own HTML with "MailCatcher" in title/body
		if r.Status == 200 && strings.Contains(body, "MailCatcher") {
			f.Unauth = true
			f.Confirmed = "MailCatcher (unauth)"
		}
	case "clickhouse":
		// /ping returns "Ok." for ClickHouse
		if r.Status == 200 && strings.TrimSpace(body) == "Ok." {
			// Probe SELECT 1 to verify the default user has no password
			r2 := Get(ctx, client, fmt.Sprintf("http://%s:%d/?query=SELECT+1", ip, sp.Port), "", 256)
			if r2.Status == 200 && strings.TrimSpace(string(r2.Body)) == "1" {
				f.Unauth = true
				f.Confirmed = "ClickHouse (unauth, default user no password)"
				f.Notes = append(f.Notes, "CRITICAL: ClickHouse default user requires no password")
				// Try version
				rv := Get(ctx, client, fmt.Sprintf("http://%s:%d/?query=SELECT+version()", ip, sp.Port), "", 64)
				if rv.Status == 200 {
					f.Confirmed = "ClickHouse " + strings.TrimSpace(string(rv.Body)) + " (unauth, default user no password)"
				}
			} else if r2.Status == 401 || strings.Contains(string(r2.Body), "Authentication failed") {
				f.Confirmed = "ClickHouse (auth required)"
			}
		}
	case "node_exporter":
		if r.Status == 200 && strings.Contains(body, "go_gc_duration_seconds") {
			f.Unauth = true
			f.Confirmed = "Prometheus node_exporter (unauth)"
		}
	case "elasticsearch":
		if r.Status == 200 && strings.Contains(body, `"cluster_name"`) {
			f.Unauth = true
			f.Confirmed = "Elasticsearch (unauth)"
		}
	case "alertmanager":
		if r.Status == 200 {
			f.Unauth = true
			f.Confirmed = "AlertManager (unauth)"
		}
	case "influxdb":
		if r.Status == 204 || (r.Status == 200 && strings.Contains(body, "influxdb")) {
			f.Confirmed = "InfluxDB"
		}
	case "minio_api":
		// /minio/health/live returns 200 (no auth) when MinIO is up.
		// The unauthenticated find here isn't "minio default creds" — that's
		// a credential test we don't do. We're just confirming MinIO presence.
		if r.Status == 200 {
			f.Confirmed = "MinIO API"
			// MinIO API root with no S3 credentials returns 403 AccessDenied
			// for ListBuckets — that's the expected secure-auth response.
			// We probe / to see if the operator left ListBuckets anonymous-readable.
			r2 := Get(ctx, NewClient(timeout), fmt.Sprintf("http://%s:%d/", ip, sp.Port), "", 1024)
			b2 := string(r2.Body)
			if r2.Status == 200 && strings.Contains(b2, "ListAllMyBucketsResult") {
				f.Unauth = true
				f.Confirmed = "MinIO API (anonymous ListBuckets allowed — CRITICAL)"
				f.Notes = append(f.Notes, "CRITICAL: MinIO root returns bucket list without auth (anonymous ListBuckets policy)")
			}
		}
	case "mlflow":
		// MLflow tracking server. /api/2.0/mlflow/experiments/list returns
		// {"experiments":[...]} when unauth. 401/403 if auth-fronted.
		if r.Status == 200 && strings.Contains(body, `"experiments"`) {
			f.Unauth = true
			f.Confirmed = "MLflow Tracking Server (unauth — experiments list returned)"
			f.Notes = append(f.Notes, "CRITICAL: MLflow API returns experiment list without authentication")
		} else if r.Status == 401 || r.Status == 403 {
			f.Confirmed = "MLflow (auth required)"
		}
	case "streamlit":
		// Streamlit /healthz returns "ok" when healthy. Streamlit apps are
		// "auth-by-app-code" — the framework itself has no auth. Marking the
		// port as open is the find; whether the app behind it has auth is
		// per-instance.
		if r.Status == 200 {
			f.Confirmed = "Streamlit app (framework has no built-in auth)"
			f.Notes = append(f.Notes, "Streamlit framework provides no auth — exposure depends on app code")
		}
	case "gradio":
		// Gradio /config returns JSON with version + UI config. Public Gradio
		// apps are common; auth is opt-in via auth= parameter at app launch.
		if r.Status == 200 && strings.Contains(body, `"version"`) {
			f.Confirmed = "Gradio app"
			// Look for auth_required field
			if strings.Contains(body, `"auth_required":false`) || !strings.Contains(body, `"auth_required"`) {
				f.Unauth = true
				f.Confirmed = "Gradio app (no auth required)"
			}
		}
	case "qdrant":
		// Qdrant /collections returns {"result":{"collections":[...]}} when unauth.
		// 401/403 if API key required.
		if r.Status == 200 && strings.Contains(body, `"collections"`) {
			f.Unauth = true
			f.Confirmed = "Qdrant (unauth — collections list returned)"
			f.Notes = append(f.Notes, "CRITICAL: Qdrant vector DB returns collection list without authentication")
		} else if r.Status == 401 || r.Status == 403 {
			f.Confirmed = "Qdrant (API key required)"
		}
	case "chromadb":
		// ChromaDB /api/v1/heartbeat returns {"nanosecond heartbeat": ...}.
		// ChromaDB has no auth by default in OSS; "tenant" feature added in v2.
		if r.Status == 200 && (strings.Contains(body, "heartbeat") || strings.Contains(body, "nanosecond")) {
			f.Unauth = true
			f.Confirmed = "ChromaDB (unauth)"
			f.Notes = append(f.Notes, "ChromaDB has no built-in auth in default OSS deployment")
		}
	}
	return f
}

// natsCharacterize probes the NATS port. NATS servers send INFO as the
// first line of every connection (no credentials required). If the
// returned INFO frame indicates "auth_required":true, auth is enforced.
// If false / absent, the server accepts unauthenticated PUBs/SUBs.
func natsCharacterize(ctx context.Context, ip string, sp ShadowPort, f ShadowFinding, timeout time.Duration) ShadowFinding {
	addr := fmt.Sprintf("%s:%d", ip, sp.Port)
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return f
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return f
	}
	banner := string(buf[:n])
	if !strings.HasPrefix(banner, "INFO ") {
		return f
	}
	// Parse "INFO { ... }" payload
	if strings.Contains(banner, `"auth_required":true`) {
		f.Confirmed = "NATS (auth required)"
	} else {
		f.Unauth = true
		f.Confirmed = "NATS (unauth — anonymous pub/sub allowed)"
		f.Notes = append(f.Notes, "CRITICAL: NATS accepts pub/sub without authentication")
		// Surface version if present
		if i := strings.Index(banner, `"version":"`); i > 0 {
			rest := banner[i+11:]
			if j := strings.Index(rest, `"`); j > 0 {
				f.Confirmed = "NATS " + rest[:j] + " (unauth — anonymous pub/sub allowed)"
			}
		}
	}
	return f
}

// memcachedCharacterize sends a `version` command and looks for the
// "VERSION x.y.z" response. Memcached has no authentication by default
// (SASL is opt-in). Open port + version response = unauth Memcached.
func memcachedCharacterize(ctx context.Context, ip string, sp ShadowPort, f ShadowFinding, timeout time.Duration) ShadowFinding {
	addr := fmt.Sprintf("%s:%d", ip, sp.Port)
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return f
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write([]byte("version\r\n"))
	if err != nil {
		return f
	}
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	if strings.HasPrefix(resp, "VERSION ") {
		f.Unauth = true
		ver := strings.TrimSpace(strings.TrimPrefix(resp, "VERSION "))
		f.Confirmed = "Memcached " + ver + " (unauth)"
		f.Notes = append(f.Notes, "CRITICAL: Memcached accepts commands without authentication")
	} else if strings.Contains(resp, "ERROR") || strings.Contains(resp, "CLIENT_ERROR") {
		f.Confirmed = "Memcached (auth required or restricted)"
	}
	return f
}

func redisCharacterize(ctx context.Context, ip string, sp ShadowPort, f ShadowFinding, timeout time.Duration) ShadowFinding {
	addr := fmt.Sprintf("%s:%d", ip, sp.Port)
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return f
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write([]byte("INFO server\r\n"))
	if err != nil {
		return f
	}
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	if strings.HasPrefix(resp, "-NOAUTH") {
		f.Confirmed = "Redis (auth required)"
		return f
	}
	if strings.Contains(resp, "redis_version") {
		f.Unauth = true
		f.Confirmed = "Redis (unauth)"
		f.Notes = append(f.Notes, "CRITICAL: Redis accepts commands without auth")
	}
	return f
}

// ExtractIP returns the host portion of a URL as an IP (or hostname if not parseable as IP).
func ExtractIP(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	host := u.Host
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}
