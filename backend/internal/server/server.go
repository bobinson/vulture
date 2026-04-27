package server

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/handler"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/internal/service"
)

type Server struct {
	mux http.Handler
}

func New(cfg *config.Config) (*Server, error) {
	if cfg.JWTSecret == "" && !cfg.LocalMode {
		return nil, fmt.Errorf("VULTURE_JWT_SECRET must be set in production mode (generate one with: openssl rand -hex 32)")
	}

	repo, pgDB, sqliteDB, err := openRepo(cfg)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	sourceSvc := service.NewSourceService(repo)
	auditSvc := service.NewAuditService(repo)
	proxyService := service.NewAgentProxyService()
	streamSvc := service.NewStreamService(proxyService)

	healthH := handler.NewHealthHandler()
	sourceH := handler.NewSourceHandler(sourceSvc)
	auditH := handler.NewAuditHandler(auditSvc)
	streamH := handler.NewStreamHandler(auditSvc, sourceSvc, streamSvc, cfg.Agents)
	agentH := handler.NewAgentHandler(cfg.Agents)
	agentH.SetReadOnly(cfg.ReadOnly)
	llmHealthH := handler.NewLLMHealthHandler(cfg.Agents)
	auditH.SetLLMHealth(llmHealthH)
	fsH := handler.NewFilesystemHandler()

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
	registerPipelineRoutes(mux, pgDB, sqliteDB, auditSvc, streamH.DiscoverService(), streamH, authMW, readOnly)

	corsMux := addCORS(mux)
	return &Server{mux: addRequestLogging(addRequestID(corsMux))}, nil
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

	// Fallback: no auth (no database available)
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
	localDevEmail    = "admin@vulture.local"
	localDevPassword = "REDACTED-DEV-PW"
	localDevName     = "Local Admin"
)

func seedLocalUser(userRepo repository.UserRepository, jwtSecret string) {
	existing, _ := userRepo.GetUserByEmail(localDevEmail)
	if existing != nil {
		return
	}
	authSvc := service.NewAuthService(userRepo, jwtSecret)
	_, err := authSvc.Register(&model.RegisterRequest{
		Email:    localDevEmail,
		Password: localDevPassword,
		Name:     localDevName,
	})
	if err != nil {
		log.Printf("warning: seed local user: %v", err)
		return
	}
	log.Println("Seeded local dev user (admin@vulture.local / REDACTED-DEV-PW)")
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

	// Stream token store: short-lived tokens for SSE authentication
	streamTokenStore := service.NewStreamTokenStore(userRepo)
	authMW.SetStreamTokenStore(streamTokenStore)
	streamH.SetStreamTokenStore(streamTokenStore)

	if cfg.LocalMode {
		authH.SetLocalMode(true)
		authMW.SetLocalMode(true)
		log.Println("Local mode enabled — auth bypass active")
	}

	// Feature 0031: API keys for machine-to-machine auth (gated by env flag)
	if cfg.APIKeysEnabled {
		registerAPIKeyRoutes(mux, pgDB, sqliteDB, authMW, readOnly)
	}

	mux.HandleFunc("/api/auth/register", RateLimit(5, time.Minute, authH.Register))
	mux.HandleFunc("/api/auth/login", RateLimit(10, time.Minute, authH.Login))
	mux.HandleFunc("/api/auth/local-session", authH.LocalSession)
	mux.HandleFunc("/api/auth/me", authMW.Require(authH.Me))

	mux.HandleFunc("/api/sources", authMW.Require(ReadOnlyGuard(readOnly, sourceH.Create)))
	mux.HandleFunc("/api/sources/", authMW.Require(ReadOnlyGuard(readOnly, sourceH.Get)))
	mux.HandleFunc("/api/stats", authMW.Require(auditH.Stats))

	// Per-principal rate limiting on audit creation (Feature 0031 Task 9).
	apiKeyRPM := 60
	if v := os.Getenv("VULTURE_APIKEY_RPM"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			apiKeyRPM = n
		}
	}
	mux.HandleFunc("/api/audits", authMW.Require(RateLimitByKey(apiKeyRPM, principalKeyFunc, ReadOnlyGuard(readOnly, auditsH))))
	mux.HandleFunc("/api/audits/", authMW.Require(ReadOnlyGuard(readOnly, auditDetailH)))
	mux.HandleFunc("/api/audits/cache", authMW.Require(auditH.CachedAudit))
	mux.HandleFunc("/api/agents", authMW.Require(agentH.List))
	mux.HandleFunc("/api/llm/health", authMW.Require(llmHealthH.ServeHTTP))
	mux.HandleFunc("/api/filesystem/browse", authMW.Require(ReadOnlyGuard(readOnly, fsH.Browse)))

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
	mux.HandleFunc("/api/lineage/", protect(ReadOnlyGuard(readOnly, lineageRouter(lineageH))))
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

func registerPipelineRoutes(mux *http.ServeMux, pgDB *sql.DB, sqliteDB *sql.DB, auditSvc service.AuditService, discoverSvc service.DiscoverService, streamH *handler.StreamHandler, protect authWrapper, readOnly bool) {
	var pipelineRepo repository.PipelineRepository
	if pgDB != nil {
		pipelineRepo = repository.NewPostgresPipelineRepo(pgDB)
	} else if sqliteDB != nil {
		pipelineRepo = repository.NewSQLitePipelineRepo(sqliteDB)
	}
	if pipelineRepo == nil {
		return
	}
	pipelineSvc := service.NewPipelineService(pipelineRepo, auditSvc, discoverSvc)
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
