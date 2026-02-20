package server

import (
	"database/sql"
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

func New(cfg *config.Config) *Server {
	repo, sqliteDB, err := openRepo(cfg)
	if err != nil {
		panic("open database: " + err.Error())
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

	pgDB := getPostgresDB(cfg)

	// Build route handler functions
	auditsHandler := auditsRouter(auditH)
	auditDetailHandler := auditDetailRouter(auditH, streamH)

	registerAPIRoutes(mux, pgDB, sqliteDB, cfg, sourceH, auditH, auditsHandler, auditDetailHandler, agentH, fsH)
	registerMemoryRoutes(mux, pgDB, sqliteDB, streamH)
	registerLineageRoutes(mux, pgDB, sqliteDB, streamH)

	corsMux := addCORS(mux)
	return &Server{mux: addRequestLogging(addRequestID(corsMux))}
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
		if r.Method == http.MethodGet {
			auditH.Get(w, r)
			return
		}
		writeNotFound(w)
	}
}

func isLineagePath(path string) bool {
	return strings.HasSuffix(path, "/lineage")
}

func registerAPIRoutes(
	mux *http.ServeMux, pgDB *sql.DB, sqliteDB *sql.DB, cfg *config.Config,
	sourceH *handler.SourceHandler, auditH *handler.AuditHandler,
	auditsH, auditDetailH http.HandlerFunc,
	agentH *handler.AgentHandler, fsH *handler.FilesystemHandler,
) {
	var userRepo repository.UserRepository
	if pgDB != nil {
		userRepo = repository.NewPostgresUserRepo(pgDB)
	} else if sqliteDB != nil {
		userRepo = repository.NewSQLiteUserRepo(sqliteDB)
		seedLocalUser(userRepo, cfg.JWTSecret)
	}

	if userRepo != nil {
		registerAuthRoutes(mux, userRepo, cfg, sourceH, auditH, auditsH, auditDetailH, agentH, fsH)
		return
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
) {
	authSvc := service.NewAuthService(userRepo, cfg.JWTSecret)
	authH := handler.NewAuthHandler(authSvc)
	authMW := handler.NewAuthMiddleware(authSvc)

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
}

func registerMemoryRoutes(mux *http.ServeMux, pgDB *sql.DB, sqliteDB *sql.DB, streamH *handler.StreamHandler) {
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

	mux.HandleFunc("/api/memories/search", memoryH.Search)
	mux.HandleFunc("/api/memories/by-path", memoryH.ListByCodebasePath)
	mux.HandleFunc("/api/memories", memoryH.ListByAudit)
	mux.HandleFunc("/api/memories/", memoryRouter(memoryH))
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

func registerLineageRoutes(mux *http.ServeMux, pgDB *sql.DB, sqliteDB *sql.DB, streamH *handler.StreamHandler) {
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

	mux.HandleFunc("/api/lineage", lineageH.List)
	mux.HandleFunc("/api/lineage/", lineageRouter(lineageH))
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

func (s *Server) Handler() http.Handler {
	return s.mux
}

func openRepo(cfg *config.Config) (repository.AuditRepository, *sql.DB, error) {
	if cfg.DBDSN != "" {
		repo, err := repository.NewPostgresRepo(cfg.DBDSN)
		return repo, nil, err
	}
	repo, err := repository.NewSQLiteRepo(cfg.DBPath)
	if err != nil {
		return nil, nil, err
	}
	return repo, repo.DB(), nil
}

func getPostgresDB(cfg *config.Config) *sql.DB {
	if cfg.DBDSN == "" {
		return nil
	}
	db, err := sql.Open("postgres", cfg.DBDSN)
	if err != nil {
		return nil
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	return db
}

func writeNotFound(w http.ResponseWriter) {
	http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
}
