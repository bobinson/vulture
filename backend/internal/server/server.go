package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vulture/backend/internal/assets"
	"github.com/vulture/backend/internal/broker/dialect"
	brokerserve "github.com/vulture/backend/internal/broker/serve"
	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/cwe"
	"github.com/vulture/backend/internal/handler"
	"github.com/vulture/backend/internal/localdev"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/pluginsupervisor"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/internal/service"
	"github.com/vulture/backend/internal/staging"
	"github.com/vulture/backend/pkg/pluginregistry"
	"github.com/vulture/backend/pkg/stagerouter"
)

type Server struct {
	mux        http.Handler
	plugins    pluginregistry.Registry
	supervisor *pluginsupervisor.Supervisor
	broker     *brokerserve.Broker
}

// Supervisor returns the plugin runtime supervisor (may be nil if
// the registry didn't build or no container plugins are installed).
// Used by the graceful-shutdown path to call StopAll.
func (s *Server) Supervisor() *pluginsupervisor.Supervisor { return s.supervisor }

// Broker returns the assembled LLM broker (feature 0064). Always non-nil;
// its Enabled flag is false when the broker is off / not on Postgres. The
// serve entrypoint mounts Broker().Handler on the internal listener.
func (s *Server) Broker() *brokerserve.Broker { return s.broker }

// New constructs the production server. The plugin registry is built
// fresh per call from DefaultLoadOptions; tests that need a controlled
// registry should call NewWithRegistry instead.
func New(cfg *config.Config) (*Server, error) {
	reg, err := pluginregistry.Build(
		pluginregistry.DefaultLoadOptions(),
		pluginregistry.DefaultStatePath(),
	)
	if err != nil {
		return nil, fmt.Errorf("plugin registry: %w", err)
	}
	return NewWithRegistry(cfg, reg)
}

// NewWithRegistry constructs a Server with a caller-supplied plugin
// registry. Used by tests to inject a deterministic registry and to
// avoid sharing global state across t.Run iterations.
func NewWithRegistry(cfg *config.Config, reg pluginregistry.Registry) (*Server, error) {
	// 0036 Phase 3 (M9) — JWT secret must be set AND long enough.
	if err := validateJWTSecret(cfg.JWTSecret, cfg.LocalMode); err != nil {
		return nil, err
	}

	// 0065 F2: honor X-Forwarded-For only from configured trusted proxies.
	if err := ConfigureTrustedProxies(cfg.TrustedProxies); err != nil {
		return nil, fmt.Errorf("configure trusted proxies: %w", err)
	}

	repo, pgDB, sqliteDB, err := openRepo(cfg)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// 0065 §L6: an unauthenticated API (no user store) may run only in
	// loopback-bound local mode; refuse a non-local posture, where the whole
	// API could be reached without credentials (directly or via a same-host
	// proxy). Fail-closed even if openRepo ever gains a degraded no-DB path.
	if err := validateAuthStoreForNonLocalMode(pgDB != nil || sqliteDB != nil, cfg.LocalMode); err != nil {
		return nil, err
	}

	// Feature 0064 §25.2/§29: assemble the LLM broker when enabled, on whichever
	// store the deployment uses — Postgres (Mode B, multi-replica) OR SQLite
	// (Mode A / native Mode E). Off → an inert Disabled() broker, so callers need
	// no nil checks and Mode A default (broker off) is completely unchanged.
	broker := brokerserve.Disabled()
	if cfg.Broker.Enabled {
		var brokerDB *sql.DB
		var brokerDialect dialect.Kind
		switch {
		case pgDB != nil:
			brokerDB, brokerDialect = pgDB, dialect.Postgres
		case sqliteDB != nil:
			brokerDB, brokerDialect = sqliteDB, dialect.SQLite
		}
		if brokerDB != nil {
			b, berr := brokerserve.Build(cfg.Broker, cfg.LLMModel, brokerDB, brokerDialect)
			if berr != nil {
				return nil, fmt.Errorf("build llm broker: %w", berr)
			}
			broker = b
		}
	}

	var supervisor *pluginsupervisor.Supervisor
	if reg != nil {
		all := reg.All()
		enabled := reg.Enabled()
		log.Printf("plugin registry: %d plugins (%d enabled)", len(all), len(enabled))

		// Feature 0052: wire the runtime supervisor for container
		// plugins. Disabled via VULTURE_DISABLE_SUPERVISOR=true so
		// operators on docker-less hosts (mode E native install)
		// can run the in-tree agents without docker.
		if os.Getenv("VULTURE_DISABLE_SUPERVISOR") != "true" {
			supervisor = pluginsupervisor.New(reg, pluginsupervisor.Options{
				Network: envOrDefault("VULTURE_SUPERVISOR_NETWORK", "vulture"),
				// Single source of truth shared with the stream dispatch
				// staging, so the mount source and the staging destination
				// can never drift (feature 0058 R11).
				AuditsDir: staging.AuditsDirFromEnv(),
				LocalMode: cfg.LocalMode,
			})
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			if acts, err := supervisor.Reconcile(ctx); err != nil {
				log.Printf("[supervisor] initial reconcile error (continuing in degraded mode): %v", err)
			} else if len(acts) > 0 {
				log.Printf("[supervisor] reconcile complete: %d actions", len(acts))
			}
		}
	}

	// Feature 0058 P0d: startup sweep of crash-orphaned staged source
	// trees. Local mode only — the only mode that stages into the
	// staging root (compose agents read the shared source-cache volume).
	// No audits are active at boot, so every entry is an orphan.
	// Best-effort: a sweep failure never blocks startup.
	if cfg.LocalMode {
		// Backgrounded: RemoveAll over many crash-orphaned trees can take
		// minutes on slow disks and must never delay serving (simplify
		// review E6). New audits use fresh audit-id dirs, so the sweep
		// cannot race them.
		go func() {
			if err := staging.Sweep(staging.AuditsDirFromEnv(), func(string) bool { return false }); err != nil {
				log.Printf("[staging] startup sweep error (continuing): %v", err)
			}
		}()
	}

	sourceSvc := service.NewSourceService(repo, cfg.SourceRoot, cfg.LocalMode)
	auditSvc := service.NewAuditService(repo)
	proxyService := service.NewAgentProxyService(broker)
	// Feature 0049: stream service consults the plugin registry via
	// stagerouter for capability-based dispatch. When the registry
	// built successfully, the router is wired and used for every
	// audit. The VULTURE_STAGE_ROUTER feature flag was removed once
	// the router shipped cleanly through 0050-0053. The nil-router
	// fallback in NewStreamService remains for degraded-mode startup.
	var streamSvc service.StreamService
	if reg != nil {
		// Feature 0050: stream service consults the CWE normalisation
		// layer when matching prove-stage capabilities. The legacy
		// constructors set a passthrough layer, so existing 0049
		// behaviour is preserved for non-prove stages.
		router := stagerouter.NewWithLayer(reg, cfg.Agents, cwe.New(reg))
		streamSvc = service.NewStreamServiceWithRouter(proxyService, router)
	} else {
		streamSvc = service.NewStreamService(proxyService)
	}

	healthH := handler.NewHealthHandler()
	sourceH := handler.NewSourceHandler(sourceSvc)
	auditH := handler.NewAuditHandler(auditSvc)
	streamH := handler.NewStreamHandler(auditSvc, sourceSvc, streamSvc, cfg.Agents)
	streamH.SetBrokerRevoker(broker) // 0064 §6/M3: revoke run tokens at terminal state (no-op when off)
	agentH := handler.NewAgentHandler(cfg.Agents)
	agentH.SetReadOnly(cfg.ReadOnly)
	// G1: surface enabled registry plugins (e.g. semgrep) in /api/agents so the
	// UI selector and results filter can see them — not just the built-ins.
	if reg != nil {
		agentH.SetPluginRegistry(reg, stagerouter.NewURLResolver(cfg.Agents).Resolve)
	}
	llmHealthH := handler.NewLLMHealthHandler(cfg.Agents)
	auditH.SetLLMHealth(llmHealthH)
	// 0071: POST /api/audits dispatches the run in the background. Without this
	// wiring an audit is created and never runs unless someone opens its stream.
	auditH.SetDispatcher(streamH)
	fsH := handler.NewFilesystemHandler()
	// 0036 Phase 3 — confine filesystem browse to cfg.SourceRoot when
	// set. Empty SourceRoot = legacy denylist-only behaviour.
	fsH.SetSourceRoot(cfg.SourceRoot)

	mux := http.NewServeMux()
	mux.Handle("/health", healthH)

	// Build route handler functions
	auditsHandler := auditsRouter(auditH)
	auditDetailHandler := auditDetailRouter(auditH, streamH)

	readOnly := cfg.ReadOnly
	authMW := registerAPIRoutes(mux, pgDB, sqliteDB, cfg, sourceH, auditH, auditsHandler, auditDetailHandler, agentH, llmHealthH, fsH, streamH, readOnly)
	registerWebhookService(pgDB, sqliteDB, streamH)
	registerMemoryRoutes(mux, pgDB, sqliteDB, streamH, authMW, readOnly)
	registerLineageRoutes(mux, pgDB, sqliteDB, streamH, auditH, authMW, readOnly)
	registerProveRoutes(mux, pgDB, sqliteDB, streamH, auditH, authMW, readOnly)
	registerDiscoverRoutes(mux, pgDB, sqliteDB, streamH, authMW, readOnly)
	registerPipelineRoutes(mux, pgDB, sqliteDB, auditSvc, streamH.DiscoverService(), streamH, reg, authMW, readOnly)

	// Install-mode-only: register the embedded SPA last so any
	// unrecognized GET falls through to the static handler with the
	// security-headers middleware (S6, S13, S14). Dev mode keeps
	// the existing Vite-proxy path.
	if localdev.DetectMode() == localdev.ModeInstall {
		registerStaticHandler(mux)
	}

	// 0036 Phase 3 (H9): refuse to start in LocalMode unless we're
	// binding to a loopback interface. Wiring lives here so it covers
	// every entry point that calls server.New (CLI, daemon, tests).
	if err := validateLoopbackForLocalMode(cfg.ListenAddr, cfg.LocalMode); err != nil {
		return nil, err
	}
	// 0036 Phase 3 — Mode B without an agent token is a credential-
	// less HTTP path into each agent service. Refuse to start when
	// VULTURE_LOCAL_MODE is false AND VULTURE_AGENT_TOKEN is empty.
	// The Python agent side already rejects untokened requests when
	// VULTURE_AGENT_TOKEN is set; this complements by ensuring the
	// operator can't accidentally deploy Mode B without setting it.
	if err := validateAgentTokenForNonLocalMode(cfg.AgentToken, cfg.LocalMode); err != nil {
		return nil, err
	}
	// 0036 Phase 3 (C3): allowlist-driven CORS replaces the previous
	// wildcard. Empty CORSAllowedOrigins is the strict default (no
	// cross-origin allowed).
	corsMux := addCORSWithAllowlist(mux, cfg.CORSAllowedOrigins)
	return &Server{
		mux:        addRequestLogging(addRequestID(corsMux)),
		plugins:    reg,
		supervisor: supervisor,
		broker:     broker,
	}, nil
}

// envOrDefault returns the value of `key` from the environment, or
// `def` if unset/empty.
func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// registerStaticHandler attaches the embedded SPA handler to "/"
// (the catch-all). The SPA fallback exclusion (S6) is enforced
// inside handler.StaticHandler — API paths get a real 404.
func registerStaticHandler(mux *http.ServeMux) {
	mux.Handle("/", handler.StaticHandler(assets.FrontendFS()))
}

func auditsRouter(auditH *handler.AuditHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			auditH.Create(w, r)
		case http.MethodGet:
			auditH.List(w, r)
		default:
			writeNotFound(w)
		}
	}
}

// isCancelPath matches /api/audits/{id}/cancel.
func isCancelPath(p string) bool {
	return strings.HasSuffix(p, "/cancel") && strings.HasPrefix(p, "/api/audits/")
}

func auditDetailRouter(auditH *handler.AuditHandler, streamH *handler.StreamHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if isStreamTokenPath(r.URL.Path) {
			streamH.CreateStreamToken(w, r)
			return
		}
		if isStreamPath(r.URL.Path) {
			streamH.ServeHTTP(w, r)
			return
		}
		if isLineagePath(r.URL.Path) && r.Method == http.MethodGet {
			if lh := streamH.LineageHandler(); lh != nil {
				lh.GetByAudit(w, r)
				return
			}
			writeNotFound(w)
			return
		}
		if isProveResultsPath(r.URL.Path) && r.Method == http.MethodGet {
			if ph := streamH.ProveHandler(); ph != nil {
				ph.GetResults(w, r)
				return
			}
			writeNotFound(w)
			return
		}
		if isProveSummaryPath(r.URL.Path) && r.Method == http.MethodGet {
			if ph := streamH.ProveHandler(); ph != nil {
				ph.GetSummary(w, r)
				return
			}
			writeNotFound(w)
			return
		}
		if isDiscoverResultPath(r.URL.Path) && r.Method == http.MethodGet {
			if dh := streamH.DiscoverHandler(); dh != nil {
				dh.GetByAudit(w, r)
				return
			}
			writeNotFound(w)
			return
		}
		// Feature 0080. Routed HERE, not registered as its own mux pattern,
		// because /api/audits/ is registered from two mutually exclusive
		// branches (registerAuthRoutes vs the local-mode fallback) and both
		// install this same handler value -- so one edit covers both and cannot
		// 404 in one mode. The method check lives inside CancelRun.
		if isCancelPath(r.URL.Path) {
			streamH.CancelRun(w, r)
			return
		}
		if isComparisonPath(r.URL.Path) && r.Method == http.MethodGet {
			auditH.Compare(w, r)
			return
		}
		if r.Method == http.MethodGet {
			auditH.Get(w, r)
			return
		}
		writeNotFound(w)
	}
}

func isStreamTokenPath(path string) bool {
	return strings.HasSuffix(path, "/stream-token")
}

func isComparisonPath(path string) bool {
	return strings.HasSuffix(path, "/comparison")
}

func isLineagePath(path string) bool {
	return strings.HasSuffix(path, "/lineage")
}

func isProveResultsPath(path string) bool {
	return strings.HasSuffix(path, "/prove-results")
}

func isProveSummaryPath(path string) bool {
	return strings.HasSuffix(path, "/prove-summary")
}

func isDiscoverResultPath(path string) bool {
	return strings.HasSuffix(path, "/discover-result")
}

// wrapFunc optionally wraps a handler with auth middleware.
// When mw is nil (no-auth fallback), it returns the handler as-is.
type authWrapper func(http.HandlerFunc) http.HandlerFunc

func noopAuth(h http.HandlerFunc) http.HandlerFunc { return h }

func registerAPIRoutes(
	mux *http.ServeMux, pgDB *sql.DB, sqliteDB *sql.DB, cfg *config.Config,
	sourceH *handler.SourceHandler, auditH *handler.AuditHandler,
	auditsH, auditDetailH http.HandlerFunc,
	agentH *handler.AgentHandler, llmHealthH *handler.LLMHealthHandler,
	fsH *handler.FilesystemHandler,
	streamH *handler.StreamHandler,
	readOnly bool,
) authWrapper {
	var userRepo repository.UserRepository
	if pgDB != nil {
		userRepo = repository.NewPostgresUserRepo(pgDB)
	} else if sqliteDB != nil {
		userRepo = repository.NewSQLiteUserRepo(sqliteDB)
	}
	if userRepo != nil && cfg.LocalMode {
		seedLocalUser(userRepo, cfg.JWTSecret)
	}

	if userRepo != nil {
		return registerAuthRoutes(mux, userRepo, cfg, sourceH, auditH, auditsH, auditDetailH, agentH, llmHealthH, fsH, streamH, readOnly, pgDB, sqliteDB)
	}

	// Fallback: no user store (no database). NewWithRegistry's
	// validateAuthStoreForNonLocalMode guarantees this branch is reachable ONLY
	// in local mode (loopback-bound), so these unauthenticated routes are
	// confined to the host and never exposed on a non-local interface (0065 §L6).
	mux.HandleFunc("/api/sources", ReadOnlyGuard(readOnly, sourceH.Create))
	mux.HandleFunc("/api/sources/", ReadOnlyGuard(readOnly, sourceH.Get))
	mux.HandleFunc("/api/stats", auditH.Stats)
	mux.HandleFunc("/api/audits", ReadOnlyGuard(readOnly, auditsH))
	mux.HandleFunc("/api/audits/", ReadOnlyGuard(readOnly, auditDetailH))
	mux.HandleFunc("/api/audits/cache", auditH.CachedAudit)
	mux.HandleFunc("/api/agents", agentH.List)
	mux.Handle("/api/llm/health", llmHealthH)
	mux.HandleFunc("/api/filesystem/browse", ReadOnlyGuard(readOnly, fsH.Browse))
	return noopAuth
}

const (
	localDevEmail = "admin@vulture.local"
	localDevName  = "Local Admin"
)

// resolveLocalDevPassword returns the password to use when seeding the
// admin@vulture.local account. Order of resolution:
//
//  1. $VULTURE_LOCAL_DEV_PASSWORD env var (operator override; persists
//     across restarts; written to config/.env by install.sh).
//  2. CSPRNG-generated 16-byte hex if env var is unset.
//
// A historical hardcoded local-dev admin default (an early-commit
// backdoor that, if exposed via Mode B, was a public-internet admin
// login) is rejected by hash rather than by literal — the literal was
// scrubbed from git history (0036 Phase 4), so it must not reappear in
// source. knownWeakDevPasswordHash is its SHA-256.
const knownWeakDevPasswordHash = "acf06e1920ea3a42ab6607d99a359784f0de53e6c9cddff86027aef883c6b533"

func resolveLocalDevPassword() (pw string, generated bool, err error) {
	if v := os.Getenv("VULTURE_LOCAL_DEV_PASSWORD"); v != "" {
		// SHA-256 is CORRECT here and a password KDF would be wrong.
		//
		// CodeQL's go/weak-sensitive-data-hashing fires on sha256(password),
		// and its advice — Argon2/scrypt/bcrypt/PBKDF2 — is aimed at password
		// STORAGE, where slowness is what defeats offline brute force. This is
		// not storage and not authentication. It is a one-element DENYLIST
		// FINGERPRINT: the operator's value is compared against the hash of a
		// single historical hardcoded default so that literal need not reappear
		// in source (it was scrubbed from git history, 0036 Phase 4).
		//
		// The hash is never persisted, never transmitted, and never used to
		// verify anyone. Preimage resistance is the only property required, and
		// SHA-256 has it.
		//
		// Why not bcrypt: not because a salted KDF cannot express a fixed
		// comparison — it can, and model/api_key.go already does it via
		// bcrypt.CompareHashAndPassword, which carries its salt inside the
		// hash string. The blocker is that the historical default's PLAINTEXT
		// is gone: it was scrubbed in 0036 Phase 4 and only its SHA-256
		// survives, so no one can generate a bcrypt digest of it now. Any
		// replacement would still have to hash the operator's input with
		// something to compare against what we do have. Separately, with
		// exactly ONE candidate input a work factor buys nothing an attacker
		// cares about — the value it protects is a published historical
		// default.
		//
		// If the plaintext is ever recovered, switching to a bcrypt digest
		// would remove this alert at the root and is the preferred fix.
		//
		// codeql[go/weak-sensitive-data-hashing]
		sum := sha256.Sum256([]byte(v))
		if hex.EncodeToString(sum[:]) == knownWeakDevPasswordHash {
			return "", false, fmt.Errorf(
				"VULTURE_LOCAL_DEV_PASSWORD is set to a known-weak historical " +
					"default; unset it or pick a strong value")
		}
		return v, false, nil
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", false, fmt.Errorf("CSPRNG read: %w", err)
	}
	return hex.EncodeToString(buf), true, nil
}

// localDevPasswordPath is where the generated local-dev password is written
// instead of being logged. Honors $VULTURE_LOCAL_DEV_PASSWORD_FILE, else sits
// beside the database so it shares that directory's lifecycle and permissions.
func localDevPasswordPath() string {
	if v := strings.TrimSpace(os.Getenv("VULTURE_LOCAL_DEV_PASSWORD_FILE")); v != "" {
		return v
	}
	if db := strings.TrimSpace(os.Getenv("VULTURE_DB_PATH")); db != "" {
		return filepath.Join(filepath.Dir(db), "local-dev-password")
	}
	return filepath.Join(os.TempDir(), "vulture-local-dev-password")
}

// writeLocalDevPassword persists the seeded credential 0600 so an operator can
// still log in. Failure is reported WITHOUT the password: a write error must not
// become the leak the file exists to prevent.
func writeLocalDevPassword(pw string) error {
	path := localDevPasswordPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(pw+"\n"), 0o600)
}

func seedLocalUser(userRepo repository.UserRepository, jwtSecret string) {
	existing, _ := userRepo.GetUserByEmail(localDevEmail)
	if existing != nil {
		return
	}
	pw, generated, err := resolveLocalDevPassword()
	if err != nil {
		log.Printf("warning: seed local user: %v", err)
		return
	}
	authSvc := service.NewAuthService(userRepo, jwtSecret)
	if _, err := authSvc.Register(&model.RegisterRequest{
		Email:    localDevEmail,
		Password: pw,
		Name:     localDevName,
	}); err != nil {
		log.Printf("warning: seed local user: %v", err)
		return
	}
	if generated {
		if err := writeLocalDevPassword(pw); err != nil {
			log.Printf("warning: could not write the local dev password file: %v", err)
			log.Printf("  set VULTURE_LOCAL_DEV_PASSWORD to choose the password yourself")
			return
		}
		// The password is deliberately NOT logged. It is a real credential for a
		// real account, logs are routinely shipped to aggregators and pasted into
		// issues, and a local-dev account is still an account. The operator gets a
		// deterministic way to retrieve it instead.
		log.Printf("Seeded local dev user: %s (password written to %s, mode 0600)",
			localDevEmail, localDevPasswordPath())
		log.Printf("  ^ password regenerates every restart unless you export VULTURE_LOCAL_DEV_PASSWORD")
	} else {
		log.Printf("Seeded local dev user: %s (password from $VULTURE_LOCAL_DEV_PASSWORD)", localDevEmail)
	}
}

func registerAuthRoutes(
	mux *http.ServeMux, userRepo repository.UserRepository, cfg *config.Config,
	sourceH *handler.SourceHandler, auditH *handler.AuditHandler,
	auditsH, auditDetailH http.HandlerFunc,
	agentH *handler.AgentHandler, llmHealthH *handler.LLMHealthHandler,
	fsH *handler.FilesystemHandler,
	streamH *handler.StreamHandler,
	readOnly bool,
	pgDB *sql.DB, sqliteDB *sql.DB,
) authWrapper {
	authSvc := service.NewAuthService(userRepo, cfg.JWTSecret)
	authH := handler.NewAuthHandler(authSvc)
	authMW := handler.NewAuthMiddleware(authSvc)

	// 0065 F6/A1: bounded, oracle-free login throttle keyed on (email, client-IP),
	// configurable via VULTURE_LOGIN_LOCKOUT_MAX / _WINDOW_SEC (defaults 5 / 900s).
	// Sits behind the per-IP RateLimit on /api/auth/login (double-bounded).
	authH.SetLoginThrottle(
		NewLoginThrottle(cfg.LoginLockoutMax, time.Duration(cfg.LoginLockoutWindowSec)*time.Second),
		realClientIP)

	// Stream token store: short-lived tokens for SSE authentication
	streamTokenStore := service.NewStreamTokenStore(userRepo)
	authMW.SetStreamTokenStore(streamTokenStore)
	streamH.SetStreamTokenStore(streamTokenStore)

	if cfg.LocalMode {
		authH.SetLocalMode(true)
		authMW.SetLocalMode(true)
		// 0036 Phase 3 (H7): defence-in-depth Host check on the
		// passwordless /api/auth/local-session endpoint.
		handler.SetLoopbackHostCheck(isLoopbackHost)
		log.Println("Local mode enabled — auth bypass active")
	}

	// Feature 0031: API keys for machine-to-machine auth (gated by env flag)
	if cfg.APIKeysEnabled {
		registerAPIKeyRoutes(mux, pgDB, sqliteDB, authMW, readOnly)
	}

	// 0065 §H7/§M1/§R7: open self-registration is on by default only in
	// local mode; in Mode B it is closed unless explicitly enabled. When
	// closed, the endpoint returns a JSON 403 (the server package has no
	// access to handler.writeError, so it writes the body directly).
	if cfg.AllowOpenRegistration {
		mux.HandleFunc("/api/auth/register", RateLimit(5, time.Minute, authH.Register))
	} else {
		mux.HandleFunc("/api/auth/register", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"open registration disabled; contact an administrator"}`))
		})
	}
	// 0065 §H7: admin-gated user provisioning so default-off Mode B can
	// still add users. Reuses Register hashing but never self-authenticates
	// the created user.
	mux.HandleFunc("/api/admin/users", authMW.Require(handler.RequireRole("admin", ReadOnlyGuard(readOnly, authH.AdminCreateUser))))
	mux.HandleFunc("/api/auth/login", RateLimit(10, time.Minute, authH.Login))
	mux.HandleFunc("/api/auth/local-session", authH.LocalSession)
	mux.HandleFunc("/api/auth/me", authMW.Require(authH.Me))

	mux.HandleFunc("/api/sources", authMW.Require(handler.RequireWrite(ReadOnlyGuard(readOnly, sourceH.Create))))
	mux.HandleFunc("/api/sources/", authMW.Require(ReadOnlyGuard(readOnly, sourceH.Get)))
	mux.HandleFunc("/api/stats", authMW.Require(auditH.Stats))

	// Per-principal rate limiting on audit creation (Feature 0031 Task 9).
	apiKeyRPM := 60
	if v := os.Getenv("VULTURE_APIKEY_RPM"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			apiKeyRPM = n
		}
	}
	// 0065 §H1: method-gated RequireWrite lets viewers GET/list while POST
	// (create) requires member/admin. Sits inside Require, outside ReadOnlyGuard.
	mux.HandleFunc("/api/audits", authMW.Require(RateLimitByKey(apiKeyRPM, principalKeyFunc, handler.RequireWrite(ReadOnlyGuard(readOnly, auditsH)))))
	mux.HandleFunc("/api/audits/", authMW.Require(ReadOnlyGuard(readOnly, auditDetailH)))
	mux.HandleFunc("/api/audits/cache", authMW.Require(auditH.CachedAudit))
	mux.HandleFunc("/api/agents", authMW.Require(agentH.List))
	mux.HandleFunc("/api/llm/health", authMW.Require(llmHealthH.ServeHTTP))
	mux.HandleFunc("/api/filesystem/browse", authMW.Require(ReadOnlyGuard(readOnly, fsH.Browse)))

	// Feature 0045: finding label endpoint (writes audit_memories.user_label).
	// SH2 rate-limit: 60 POST/min/user via RateLimitByKey.
	var rawDB *sql.DB
	dialect := "sqlite"
	if pgDB != nil {
		rawDB = pgDB
		dialect = "postgres"
	} else if sqliteDB != nil {
		rawDB = sqliteDB
	}
	if rawDB != nil {
		labelH := handler.NewFindingLabelHandler(rawDB, dialect)
		mux.HandleFunc("/api/findings/", authMW.Require(
			RateLimitByKey(60, principalKeyFunc, handler.RequireWrite(ReadOnlyGuard(readOnly, labelH.Handle)))))

		// L4 memory_prior lookup — runs in the stream handler's drain
		// path; nil-safe when DB not configured.
		handler.SetMemoryLookup(service.NewMemoryPriorLookup(rawDB, dialect))
	}

	log.Println("Auth endpoints enabled")
	return authMW.Require
}

func registerMemoryRoutes(mux *http.ServeMux, pgDB *sql.DB, sqliteDB *sql.DB, streamH *handler.StreamHandler, protect authWrapper, readOnly bool) {
	var memRepo repository.MemoryRepository
	if pgDB != nil {
		memRepo = repository.NewPostgresMemoryRepo(pgDB)
	} else if sqliteDB != nil {
		var err error
		memRepo, err = repository.NewSQLiteMemoryRepo(sqliteDB)
		if err != nil {
			log.Printf("WARNING: failed to initialize SQLite memory repo: %v", err)
			return
		}
		log.Println("Memory routes enabled (SQLite)")
	} else {
		return
	}
	memorySvc := service.NewMemoryService(memRepo)
	memoryH := handler.NewMemoryHandler(memorySvc)

	streamH.SetMemoryService(memorySvc)

	mux.HandleFunc("/api/memories/search", protect(memoryH.Search))
	mux.HandleFunc("/api/memories/by-path", protect(memoryH.ListByCodebasePath))
	mux.HandleFunc("/api/memories", protect(memoryH.ListByAudit))
	mux.HandleFunc("/api/memories/", protect(ReadOnlyGuard(readOnly, memoryRouter(memoryH))))
}

func memoryRouter(memoryH *handler.MemoryHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/edges") && r.Method == http.MethodGet {
			memoryH.GetEdges(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			memoryH.Get(w, r)
		case http.MethodPatch:
			memoryH.UpdateRemediation(w, r)
		default:
			writeNotFound(w)
		}
	}
}

func registerLineageRoutes(mux *http.ServeMux, pgDB *sql.DB, sqliteDB *sql.DB, streamH *handler.StreamHandler, auditH *handler.AuditHandler, protect authWrapper, readOnly bool) {
	var lineageRepo repository.LineageRepository
	if pgDB != nil {
		lineageRepo = repository.NewPostgresLineageRepo(pgDB)
	} else if sqliteDB != nil {
		lineageRepo = repository.NewSQLiteLineageRepo(sqliteDB)
	} else {
		return
	}
	lineageSvc := service.NewLineageService(lineageRepo)
	lineageH := handler.NewLineageHandler(lineageSvc)

	streamH.SetLineageService(lineageSvc)
	streamH.SetLineageHandler(lineageH)
	auditH.SetLineageRepo(lineageRepo) // enrich /comparison summaries with VLT-XXXX refs

	mux.HandleFunc("/api/lineage", protect(lineageH.List))
	// 0065 §H1: method-gated write guard — viewer GET stays open, PATCH
	// (status update) requires member/admin.
	mux.HandleFunc("/api/lineage/", protect(handler.RequireWrite(ReadOnlyGuard(readOnly, lineageRouter(lineageH)))))
}

func lineageRouter(lineageH *handler.LineageHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/timeline") && r.Method == http.MethodGet {
			lineageH.GetTimeline(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			lineageH.Get(w, r)
		case http.MethodPatch:
			lineageH.UpdateStatus(w, r)
		default:
			writeNotFound(w)
		}
	}
}

func registerProveRoutes(mux *http.ServeMux, pgDB *sql.DB, sqliteDB *sql.DB, streamH *handler.StreamHandler, auditH *handler.AuditHandler, protect authWrapper, readOnly bool) {
	var proveRepo repository.ProveRepository
	if pgDB != nil {
		proveRepo = repository.NewPostgresProveRepo(pgDB)
	} else if sqliteDB != nil {
		proveRepo = repository.NewSQLiteProveRepo(sqliteDB)
	}
	if proveRepo == nil {
		return
	}
	proveSvc := service.NewProveService(proveRepo)
	proveH := handler.NewProveHandler(proveSvc)

	streamH.SetProveService(proveSvc)
	streamH.SetProveHandler(proveH)
	auditH.SetProveService(proveSvc)

	mux.HandleFunc("/api/prove-results", protect(proveH.GetResultsByFingerprint))

	dbType := "SQLite"
	if pgDB != nil {
		dbType = "PostgreSQL"
	}
	log.Printf("Prove routes enabled (%s)", dbType)
}

func registerDiscoverRoutes(mux *http.ServeMux, pgDB *sql.DB, sqliteDB *sql.DB, streamH *handler.StreamHandler, protect authWrapper, readOnly bool) {
	var discoverRepo repository.DiscoverRepository
	if pgDB != nil {
		discoverRepo = repository.NewPostgresDiscoverRepo(pgDB)
	} else if sqliteDB != nil {
		discoverRepo = repository.NewSQLiteDiscoverRepo(sqliteDB)
	}
	if discoverRepo == nil {
		return
	}
	discoverSvc := service.NewDiscoverService(discoverRepo)
	discoverH := handler.NewDiscoverHandler(discoverSvc)

	streamH.SetDiscoverService(discoverSvc)
	streamH.SetDiscoverHandler(discoverH)

	mux.HandleFunc("/api/discover-results", protect(discoverH.GetByTarget))
	log.Println("Discover routes enabled")
}

func registerPipelineRoutes(mux *http.ServeMux, pgDB *sql.DB, sqliteDB *sql.DB, auditSvc service.AuditService, discoverSvc service.DiscoverService, streamH *handler.StreamHandler, reg pluginregistry.Registry, protect authWrapper, readOnly bool) {
	var pipelineRepo repository.PipelineRepository
	if pgDB != nil {
		pipelineRepo = repository.NewPostgresPipelineRepo(pgDB)
	} else if sqliteDB != nil {
		pipelineRepo = repository.NewSQLitePipelineRepo(sqliteDB)
	}
	if pipelineRepo == nil {
		return
	}
	// Feature 0049 follow-up: registry-aware default scan-types
	// provider lets pipeline-driven audits include enabled external
	// scan plugins by default, not just the legacy in-tree set.
	defaultScanTypes := func() []string {
		return stagerouter.DefaultScanAgentTypes(reg, config.ScanAgentTypes())
	}
	pipelineSvc := service.NewPipelineServiceWithScanTypes(pipelineRepo, auditSvc, discoverSvc, defaultScanTypes)
	pipelineSvc.SetRunner(streamH)
	pipelineH := handler.NewPipelineHandler(pipelineSvc)

	streamH.SetPipelineService(pipelineSvc)

	mux.HandleFunc("/api/pipelines", protect(ReadOnlyGuard(readOnly, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			pipelineH.Create(w, r)
		case http.MethodGet:
			pipelineH.List(w, r)
		default:
			writeNotFound(w)
		}
	})))
	mux.HandleFunc("/api/pipelines/", protect(pipelineH.Get))
	log.Println("Pipeline routes enabled")
}

func registerWebhookService(pgDB *sql.DB, sqliteDB *sql.DB, streamH *handler.StreamHandler) {
	// TODO: add PostgresWebhookRepo when postgres_webhook_repo.go is implemented
	if sqliteDB != nil {
		webhookRepo := repository.NewSQLiteWebhookRepo(sqliteDB)
		webhookSvc := service.NewWebhookService(webhookRepo)
		streamH.SetWebhookService(webhookSvc)
		log.Println("Webhook service enabled (SQLite)")
	}
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func openRepo(cfg *config.Config) (repository.AuditRepository, *sql.DB, *sql.DB, error) {
	if cfg.DBDSN != "" {
		// Read-only viewer (mode C) connects to a writer-owned schema and
		// typically lacks DDL perms — skip the migration step.
		var repo *repository.PostgresRepo
		var err error
		if cfg.ReadOnly {
			repo, err = repository.NewPostgresRepoReadOnly(cfg.DBDSN)
		} else {
			repo, err = repository.NewPostgresRepo(cfg.DBDSN)
		}
		if err != nil {
			return nil, nil, nil, err
		}
		return repo, repo.DB(), nil, nil
	}
	repo, err := repository.NewSQLiteRepo(cfg.DBPath)
	if err != nil {
		return nil, nil, nil, err
	}
	return repo, nil, repo.DB(), nil
}

func writeNotFound(w http.ResponseWriter) {
	http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
}

// registerAPIKeyRoutes wires the /api/api-keys CRUD endpoints and enables
// API-key bearer-token auth in the AuthMiddleware. Feature 0031.
func registerAPIKeyRoutes(
	mux *http.ServeMux, pgDB *sql.DB, sqliteDB *sql.DB,
	authMW *handler.AuthMiddleware, readOnly bool,
) {
	var repo repository.APIKeyRepository
	if pgDB != nil {
		repo = repository.NewPostgresAPIKeyRepo(pgDB)
	} else if sqliteDB != nil {
		repo = repository.NewSQLiteAPIKeyRepo(sqliteDB)
	}
	if repo == nil {
		return
	}
	svc := service.NewAPIKeyService(repo)
	authMW.SetAPIKeyService(svc) // enable vk_... bearer auth

	h := handler.NewAPIKeyHandler(svc)
	mux.HandleFunc("/api/api-keys", authMW.Require(ReadOnlyGuard(readOnly, h.CreateOrList)))
	mux.HandleFunc("/api/api-keys/", authMW.Require(ReadOnlyGuard(readOnly, h.Revoke)))
	log.Println("Feature 0031: API keys enabled — endpoints registered at /api/api-keys")
}
