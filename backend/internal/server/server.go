package server

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
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
	fsH := handler.NewFilesystemHandler()

	mux := http.NewServeMux()
	mux.Handle("/health", healthH)

	// Build route handler functions
	auditsHandler := auditsRouter(auditH)
	auditDetailHandler := auditDetailRouter(auditH, streamH)

	authMW := registerAPIRoutes(mux, pgDB, sqliteDB, cfg, sourceH, auditH, auditsHandler, auditDetailHandler, agentH, fsH, streamH)
	registerMemoryRoutes(mux, pgDB, sqliteDB, streamH, authMW)
	registerLineageRoutes(mux, pgDB, sqliteDB, streamH, authMW)
	registerProveRoutes(mux, pgDB, sqliteDB, streamH, auditH, authMW)
	registerDiscoverRoutes(mux, pgDB, sqliteDB, streamH, authMW)
	registerPipelineRoutes(mux, pgDB, sqliteDB, auditSvc, streamH.DiscoverService(), streamH, authMW)

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
	agentH *handler.AgentHandler, fsH *handler.FilesystemHandler,
	streamH *handler.StreamHandler,
) authWrapper {
	var userRepo repository.UserRepository
	if pgDB != nil {
		userRepo = repository.NewPostgresUserRepo(pgDB)
	} else if sqliteDB != nil {
		userRepo = repository.NewSQLiteUserRepo(sqliteDB)
		seedLocalUser(userRepo, cfg.JWTSecret)
	}

	if userRepo != nil {
		authMW := registerAuthRoutes(mux, userRepo, cfg, sourceH, auditH, auditsH, auditDetailH, agentH, fsH, streamH)
		return authMW
	}

	// Fallback: no auth (no database available)
	mux.HandleFunc("/api/sources", sourceH.Create)
	mux.HandleFunc("/api/sources/", sourceH.Get)
	mux.HandleFunc("/api/stats", auditH.Stats)
	mux.HandleFunc("/api/audits", auditsH)
	mux.HandleFunc("/api/audits/", auditDetailH)
	mux.HandleFunc("/api/audits/cache", auditH.CachedAudit)
	mux.HandleFunc("/api/agents", agentH.List)
	mux.HandleFunc("/api/filesystem/browse", fsH.Browse)
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
	agentH *handler.AgentHandler, fsH *handler.FilesystemHandler,
	streamH *handler.StreamHandler,
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

	mux.HandleFunc("/api/auth/register", RateLimit(5, time.Minute, authH.Register))
	mux.HandleFunc("/api/auth/login", RateLimit(10, time.Minute, authH.Login))
	mux.HandleFunc("/api/auth/local-session", authH.LocalSession)
	mux.HandleFunc("/api/auth/me", authMW.Require(authH.Me))

	mux.HandleFunc("/api/sources", authMW.Require(sourceH.Create))
	mux.HandleFunc("/api/sources/", authMW.Require(sourceH.Get))
	mux.HandleFunc("/api/stats", authMW.Require(auditH.Stats))
	mux.HandleFunc("/api/audits", authMW.Require(auditsH))
	mux.HandleFunc("/api/audits/", authMW.Require(auditDetailH))
	mux.HandleFunc("/api/audits/cache", authMW.Require(auditH.CachedAudit))
	mux.HandleFunc("/api/agents", authMW.Require(agentH.List))
	mux.HandleFunc("/api/filesystem/browse", authMW.Require(fsH.Browse))

	log.Println("Auth endpoints enabled")
	return authMW.Require
}

func registerMemoryRoutes(mux *http.ServeMux, pgDB *sql.DB, sqliteDB *sql.DB, streamH *handler.StreamHandler, protect authWrapper) {
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
	mux.HandleFunc("/api/memories/", protect(memoryRouter(memoryH)))
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

func registerLineageRoutes(mux *http.ServeMux, pgDB *sql.DB, sqliteDB *sql.DB, streamH *handler.StreamHandler, protect authWrapper) {
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

	mux.HandleFunc("/api/lineage", protect(lineageH.List))
	mux.HandleFunc("/api/lineage/", protect(lineageRouter(lineageH)))
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

func registerProveRoutes(mux *http.ServeMux, pgDB *sql.DB, sqliteDB *sql.DB, streamH *handler.StreamHandler, auditH *handler.AuditHandler, protect authWrapper) {
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

func registerDiscoverRoutes(mux *http.ServeMux, pgDB *sql.DB, sqliteDB *sql.DB, streamH *handler.StreamHandler, protect authWrapper) {
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

func registerPipelineRoutes(mux *http.ServeMux, pgDB *sql.DB, sqliteDB *sql.DB, auditSvc service.AuditService, discoverSvc service.DiscoverService, streamH *handler.StreamHandler, protect authWrapper) {
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

	mux.HandleFunc("/api/pipelines", protect(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			pipelineH.Create(w, r)
		case http.MethodGet:
			pipelineH.List(w, r)
		default:
			writeNotFound(w)
		}
	}))
	mux.HandleFunc("/api/pipelines/", protect(pipelineH.Get))
	log.Println("Pipeline routes enabled")
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func openRepo(cfg *config.Config) (repository.AuditRepository, *sql.DB, *sql.DB, error) {
	if cfg.DBDSN != "" {
		repo, err := repository.NewPostgresRepo(cfg.DBDSN)
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
