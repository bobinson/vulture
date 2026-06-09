package localdev

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/vulture/backend/internal/config"
)

// Config holds local development launch configuration.
type Config struct {
	ProjectRoot  string
	DataDir      string
	BackendPort  string
	FrontendPort string
	AgentPorts   map[string]string // agent_type -> port
}

// DefaultConfig returns default local development configuration,
// reading port overrides from <projectRoot>/config.ini when present.
func DefaultConfig(projectRoot string) *Config {
	// Install mode keeps data under the install's VULTURE_HOME (so the backend's
	// SQLite DB is created + migrated there); dev keeps the historical
	// $HOME/.vulture location.
	var dataDir string
	if DetectMode() == ModeInstall {
		dataDir = DataDir(ModeInstall, projectRoot) // $VULTURE_HOME/data
		_ = os.MkdirAll(dataDir, 0o700)
	} else {
		dataDir, _ = DefaultDataDir()
	}
	ini := loadLocalINI(filepath.Join(projectRoot, "config.ini"))

	port := func(iniKey, fallback string) string {
		if v := ini["ports."+iniKey]; v != "" {
			return v
		}
		return fallback
	}

	agentPorts := make(map[string]string, len(config.AllAgents))
	for _, entry := range config.AllAgents {
		agentPorts[entry.Type] = port(entry.INIKey, entry.DefaultPort)
	}

	return &Config{
		ProjectRoot:  projectRoot,
		DataDir:      dataDir,
		BackendPort:  port("backend", "28080"),
		FrontendPort: port("frontend_host", "23001"),
		AgentPorts:   agentPorts,
	}
}

// Launcher orchestrates all local development processes.
type Launcher struct {
	cfg    *Config
	mgr    *Manager
	detect *Detect
}

// NewLauncher creates a launcher with the given config.
func NewLauncher(cfg *Config) *Launcher {
	return &Launcher{
		cfg: cfg,
		mgr: NewManager(),
	}
}

// Start launches all components and returns the process manager.
func (l *Launcher) Start(ctx context.Context) error {
	// Install mode (Mode E) runs a different stack than the dev tree: a prebuilt
	// backend binary + embedded SPA + bundled-venv agents. The dev flow below
	// (go build, vite, pip-install-editable from the project tree) does not
	// apply. See docs/features/0055 §3 correction.
	if DetectMode() == ModeInstall {
		return l.startInstallMode(ctx)
	}

	det, err := CheckPrereqs(l.cfg.ProjectRoot)
	if err != nil {
		return fmt.Errorf("prerequisites: %w", err)
	}
	l.detect = det

	// 0. Set up Ollama if available (auto-pull embedding + LLM models)
	// Must run before printBanner so env vars are set for banner display.
	l.setupOllama(ctx)

	printBanner(l.cfg)

	// 1. Install Python agent dependencies if needed. Fatal: agents can't
	// start without uvicorn, and the previous warn-and-continue behavior
	// produced a flood of cryptic ImportError messages.
	if err := l.installAgentDeps(ctx); err != nil {
		return fmt.Errorf("install agent deps: %w", err)
	}

	// 2. Start Python agents
	if err := l.startAgents(ctx); err != nil {
		return fmt.Errorf("start agents: %w", err)
	}

	// 2.5. Probe LLM health via one agent's /health and print canonical
	// message. Aborts on VULTURE_REQUIRE_LLM=true if degraded. Feature 0039.
	reportLLMHealthOrAbort(ctx, l.agentURLs())

	// 3. Start Go backend
	if err := l.startBackend(ctx); err != nil {
		return fmt.Errorf("start backend: %w", err)
	}

	// 4. Start frontend dev server
	if err := l.startFrontend(ctx); err != nil {
		return fmt.Errorf("start frontend: %w", err)
	}

	return nil
}

// setupOllama detects Ollama, auto-pulls required models, and configures
// environment variables for local embedding and LLM if no cloud API key is set.
func (l *Launcher) setupOllama(ctx context.Context) {
	if l.detect.OllamaPath == "" {
		return
	}

	if !l.detect.OllamaOK {
		log.Println("Ollama installed but not running. Start it with: ollama serve")
		return
	}

	log.Println("Ollama detected and running")

	// Only auto-configure if no cloud API key is set (don't override user choice)
	hasCloudKey := os.Getenv("OPENAI_API_KEY") != ""
	hasExplicitModel := os.Getenv("VULTURE_LLM_MODEL") != ""
	hasExplicitEmbedding := os.Getenv("VULTURE_EMBEDDING_URL") != ""

	// Auto-pull embedding model (always, even with cloud key — embeddings use Ollama locally)
	if !hasExplicitEmbedding {
		embeddingReady := OllamaHasModel("nomic-embed-text")
		if !embeddingReady {
			log.Println("  Pulling nomic-embed-text embedding model...")
			if err := OllamaPullModel(ctx, "nomic-embed-text"); err != nil {
				log.Printf("  warning: failed to pull nomic-embed-text: %v", err)
			} else {
				embeddingReady = true
				log.Println("  nomic-embed-text ready")
			}
		} else {
			log.Println("  nomic-embed-text embedding model available")
		}
		// Only set env vars if model is actually available
		if embeddingReady {
			os.Setenv("VULTURE_EMBEDDING_URL", ollamaBaseURL()+"/v1")
			os.Setenv("VULTURE_EMBEDDING_MODEL", "nomic-embed-text")
		}
	}

	// Auto-pull LLM model for agents if no cloud key
	if !hasCloudKey && !hasExplicitModel {
		llmModel := "qwen3:1.7b"
		llmReady := OllamaHasModel(llmModel)
		if !llmReady {
			log.Printf("  Pulling %s LLM model...", llmModel)
			if err := OllamaPullModel(ctx, llmModel); err != nil {
				log.Printf("  warning: failed to pull %s: %v", llmModel, err)
			} else {
				llmReady = true
				log.Printf("  %s ready", llmModel)
			}
		} else {
			log.Printf("  %s LLM model available", llmModel)
		}
		// Only configure LLM if model is actually available
		if llmReady {
			os.Setenv("VULTURE_LLM_MODEL", llmModel)
			os.Setenv("VULTURE_USE_LLM", "true")
		}
	}
}

// Manager returns the process manager for status/shutdown.
func (l *Launcher) Manager() *Manager {
	return l.mgr
}

// agentRuntime resolves the python interpreter and agents-source root for the
// current mode. Install mode uses the bundled venv (PythonBin) + runtime/agents;
// dev mode uses the detected interpreter + the project tree. (Closes the
// install-mode launcher gap — see docs/features/0055 §3 correction.)
func (l *Launcher) agentRuntime() (pythonBin, agentsDir string) {
	mode := DetectMode()
	agentsDir = AgentsRoot(mode, l.cfg.ProjectRoot)
	pythonBin = PythonBin(mode)
	if pythonBin == "" {
		pythonBin = l.detect.PythonPath
	}
	return
}

// startInstallMode runs the install-mode local stack: the prebuilt backend
// binary (API + embedded SPA), plus bundled-venv agents when a runtime is
// present. No go build, no vite, no pip-install-editable — the venv is
// pre-provisioned by install.sh (--require-hashes); first-party packages load
// via PYTHONPATH=runtime/agents.
func (l *Launcher) startInstallMode(ctx context.Context) error {
	det, err := CheckInstallPrereqs()
	if err != nil {
		return fmt.Errorf("prerequisites: %w", err)
	}
	l.detect = det
	l.setupOllama(ctx)
	printBanner(l.cfg)

	if det.PythonPath != "" && det.UvicornOK {
		if err := l.startAgents(ctx); err != nil {
			return fmt.Errorf("start agents: %w", err)
		}
		reportLLMHealthOrAbort(ctx, l.agentURLs())
	} else {
		log.Printf("agents unavailable (no bundled Python runtime at %s); "+
			"starting backend + skills only — reinstall with VULTURE_USE_SYSTEM_PYTHON=1 "+
			"and a hashed lockfile, or use Docker for agent scanning", PythonBin(ModeInstall))
	}

	if err := l.startBackend(ctx); err != nil {
		return fmt.Errorf("start backend: %w", err)
	}
	return nil
}

func (l *Launcher) installAgentDeps(ctx context.Context) error {
	// Skip if the venv (or system Python) already has uvicorn installed —
	// the typical case after a successful `scripts/vulture.sh build`. This
	// also avoids the previous race where pip and uvicorn raced and agents
	// crashed with "No module named uvicorn.__main__".
	if l.detect.UvicornOK {
		return nil
	}

	agentsDir := filepath.Join(l.cfg.ProjectRoot, "agents")
	sharedDir := filepath.Join(agentsDir, "shared")

	log.Println("installing Python agent dependencies (one-time)...")
	if err := runPipInstallEditable(ctx, l.detect.PythonPath, sharedDir); err != nil {
		return fmt.Errorf("install shared: %w", err)
	}

	for _, entry := range config.AllAgents {
		agentDir := filepath.Join(agentsDir, entry.DirName)
		if _, err := os.Stat(agentDir); os.IsNotExist(err) {
			continue
		}
		if err := runPipInstallEditable(ctx, l.detect.PythonPath, agentDir); err != nil {
			log.Printf("warning: install %s: %v", entry.DirName, err)
		}
	}

	// Verify uvicorn is importable now. If not, the agents will crash with
	// a cryptic ImportError the moment they start — abort here with a clear
	// message instead.
	if !checkPythonModule(l.detect.PythonPath, "uvicorn") {
		return fmt.Errorf("uvicorn not importable after pip install (python=%s); run: ./scripts/vulture.sh build agents", l.detect.PythonPath)
	}
	l.detect.UvicornOK = true
	return nil
}

// runPipInstallEditable runs `pip install -e <target>` synchronously against
// the given Python interpreter. Tries a normal install first, then falls back
// to --break-system-packages for PEP-668 system Pythons (Ubuntu 24.04+). When
// `python` points at a venv the first attempt always succeeds.
func runPipInstallEditable(ctx context.Context, python, target string) error {
	cmd := exec.CommandContext(ctx, python, "-m", "pip", "install", "-e", target, "-q")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err == nil {
		return nil
	}
	cmd = exec.CommandContext(ctx, python, "-m", "pip", "install", "-e", target, "-q", "--break-system-packages")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// agentURLs returns the http://localhost:<port> URL for every registered
// agent, used by reportLLMHealthOrAbort to query /health.
func (l *Launcher) agentURLs() []string {
	urls := make([]string, 0, len(config.AllAgents))
	for _, entry := range config.AllAgents {
		port, ok := l.cfg.AgentPorts[entry.Type]
		if !ok || port == "" {
			continue
		}
		urls = append(urls, "http://localhost:"+port)
	}
	return urls
}

func (l *Launcher) startAgents(ctx context.Context) error {
	pythonBin, agentsDir := l.agentRuntime()

	for _, entry := range config.AllAgents {
		agentDir := filepath.Join(agentsDir, entry.DirName)
		port := l.cfg.AgentPorts[entry.Type]

		if _, err := os.Stat(agentDir); os.IsNotExist(err) {
			log.Printf("skipping agent %s: directory not found", entry.Type)
			continue
		}
		// Build PYTHONPATH: shared + agent dir + any cross-agent deps
		pythonPath := agentsDir + "/shared:" + agentDir
		pythonPath += extraPythonPath(agentsDir, entry.Type)

		env := []string{
			"VULTURE_AGENT_PORT=" + port,
			"VULTURE_BACKEND_URL=http://localhost:" + l.cfg.BackendPort,
			"PYTHONPATH=" + pythonPath,
		}
		// Cross-agent URL: prove → discover. Defaults to the docker
		// hostname `http://agent-discover:28008` (compose mode), which
		// can't be resolved in bare-metal mode and produced
		//   "Discover agent call failed: Name or service not known"
		// in the prove agent's logs. Override with localhost when the
		// discover port is known.
		if discoverPort, ok := l.cfg.AgentPorts["discover"]; ok && discoverPort != "" {
			env = append(env, "VULTURE_DISCOVER_URL=http://localhost:"+discoverPort)
		}
		if apiKey := os.Getenv("OPENAI_API_KEY"); apiKey != "" {
			env = append(env, "OPENAI_API_KEY="+apiKey)
		}
		if baseURL := os.Getenv("OPENAI_BASE_URL"); baseURL != "" {
			env = append(env, "OPENAI_BASE_URL="+baseURL)
		}
		if model := os.Getenv("VULTURE_LLM_MODEL"); model != "" {
			env = append(env, "VULTURE_LLM_MODEL="+model)
		}
		if useLLM := os.Getenv("VULTURE_USE_LLM"); useLLM != "" {
			env = append(env, "VULTURE_USE_LLM="+useLLM)
		}
		// Pass Ollama host for LiteLLM's Ollama provider.
		// LiteLLM expects OLLAMA_API_BASE, not OLLAMA_HOST.
		ollamaHost := os.Getenv("OLLAMA_HOST")
		if ollamaHost == "" {
			ollamaHost = ollamaBaseURL()
		}
		if l.detect.OllamaOK {
			env = append(env, "OLLAMA_API_BASE="+ollamaHost)
		}
		// Pass Anthropic API key for Claude models via LiteLLM.
		if anthropicKey := os.Getenv("ANTHROPIC_API_KEY"); anthropicKey != "" {
			env = append(env, "ANTHROPIC_API_KEY="+anthropicKey)
		}
		// Pass Gemini API key for Google models via LiteLLM.
		if geminiKey := os.Getenv("GEMINI_API_KEY"); geminiKey != "" {
			env = append(env, "GEMINI_API_KEY="+geminiKey)
		}
		// Pass token efficiency configuration.
		if ctxSize := os.Getenv("VULTURE_LLM_CTX_SIZE"); ctxSize != "" {
			env = append(env, "VULTURE_LLM_CTX_SIZE="+ctxSize)
		}
		if maxOutput := os.Getenv("VULTURE_LLM_MAX_OUTPUT_TOKENS"); maxOutput != "" {
			env = append(env, "VULTURE_LLM_MAX_OUTPUT_TOKENS="+maxOutput)
		}
		if loopLimit := os.Getenv("VULTURE_LOOP_GLOBAL_LIMIT"); loopLimit != "" {
			env = append(env, "VULTURE_LOOP_GLOBAL_LIMIT="+loopLimit)
		}
		// Disable OpenAI Agents SDK tracing (avoids 400 errors from unsupported fields).
		env = append(env, "OPENAI_AGENTS_DISABLE_TRACING=1")

		err := l.mgr.Start(ctx, "agent-"+entry.Type, agentDir, env,
			pythonBin, "-m", "uvicorn", entry.Module,
			"--host", "0.0.0.0", "--port", port,
		)
		if err != nil {
			return fmt.Errorf("start agent %s: %w", entry.Type, err)
		}
		log.Printf("started agent-%s on port %s", entry.Type, port)
	}
	return nil
}

func (l *Launcher) startBackend(ctx context.Context) error {
	dbPath := filepath.Join(l.cfg.DataDir, "vulture.db")
	// If VULTURE_DB_DSN is set (e.g. Neon), use Postgres; otherwise SQLite.
	dbDSN := os.Getenv("VULTURE_DB_DSN")
	env := []string{
		"VULTURE_PORT=" + l.cfg.BackendPort,
		"VULTURE_DB_PATH=" + dbPath,
		"VULTURE_DB_DSN=" + dbDSN,
		"VULTURE_LOCAL_MODE=true",
	}
	// Set agent URL env vars from the registry
	for _, entry := range config.AllAgents {
		env = append(env, entry.EnvURLKey()+"=http://localhost:"+l.cfg.AgentPorts[entry.Type])
	}
	if apiKey := os.Getenv("OPENAI_API_KEY"); apiKey != "" {
		env = append(env, "OPENAI_API_KEY="+apiKey)
	}
	// Pass Ollama embedding configuration to backend
	if embURL := os.Getenv("VULTURE_EMBEDDING_URL"); embURL != "" {
		env = append(env, "VULTURE_EMBEDDING_URL="+embURL)
	}
	if embModel := os.Getenv("VULTURE_EMBEDDING_MODEL"); embModel != "" {
		env = append(env, "VULTURE_EMBEDDING_MODEL="+embModel)
	}
	// Pass through optional feature flags
	for _, key := range []string{
		"VULTURE_JWT_SECRET",
		"VULTURE_API_KEYS_ENABLED",
		"VULTURE_READONLY",
		"VULTURE_WEBHOOK_SECRET",
		"ANTHROPIC_API_KEY",
		"GEMINI_API_KEY",
		"OPENAI_BASE_URL",
	} {
		if v := os.Getenv(key); v != "" {
			env = append(env, key+"="+v)
		}
	}

	var bin, wd string
	var args []string
	if DetectMode() == ModeInstall {
		// Install mode: the prebuilt installed binary serves the API + embedded
		// SPA. Run it via `serve` (no go build, no project tree).
		exe, exeErr := os.Executable()
		if exeErr != nil {
			return fmt.Errorf("locate vulture binary: %w", exeErr)
		}
		bin, wd, args = exe, ResolveHome(), []string{"serve"}
	} else {
		backendDir := filepath.Join(l.cfg.ProjectRoot, "backend")
		bin, wd = filepath.Join(backendDir, "bin", "vulture"), backendDir
		// Build if binary doesn't exist
		if _, err := os.Stat(bin); os.IsNotExist(err) {
			log.Println("building backend binary...")
			buildCmd := fmt.Sprintf("cd %s && %s build -o bin/vulture ./cmd/vulture/", backendDir, l.detect.GoPath)
			buildProc := NewManager()
			if err := buildProc.Start(ctx, "go-build", backendDir, nil, "sh", "-c", buildCmd); err != nil {
				return fmt.Errorf("build backend: %w", err)
			}
			buildProc.WaitAll()
		}
	}

	cmdline := append([]string{bin}, args...)
	err := l.mgr.Start(ctx, "backend", wd, env, cmdline...)
	if err != nil {
		return fmt.Errorf("start backend: %w", err)
	}
	if dbDSN != "" {
		// Mask the password in the log line for safety.
		masked := maskDSNPassword(dbDSN)
		log.Printf("started backend on port %s (Postgres: %s)", l.cfg.BackendPort, masked)
	} else {
		log.Printf("started backend on port %s (SQLite: %s)", l.cfg.BackendPort, dbPath)
	}
	return nil
}

// maskDSNPassword returns the DSN with the password component replaced by
// ***. Best-effort string surgery — handles the postgres://user:pass@host
// form. Returns the input unchanged if the shape doesn't match.
func maskDSNPassword(dsn string) string {
	at := strings.LastIndex(dsn, "@")
	scheme := strings.Index(dsn, "://")
	if at == -1 || scheme == -1 || at <= scheme+3 {
		return dsn
	}
	creds := dsn[scheme+3 : at]
	colon := strings.Index(creds, ":")
	if colon == -1 {
		return dsn
	}
	user := creds[:colon]
	return dsn[:scheme+3] + user + ":***" + dsn[at:]
}

func (l *Launcher) startFrontend(ctx context.Context) error {
	frontendDir := filepath.Join(l.cfg.ProjectRoot, "frontend")

	// Check if vite binary exists (node_modules may be incomplete)
	viteBin := filepath.Join(frontendDir, "node_modules", ".bin", "vite")
	if _, err := os.Stat(viteBin); os.IsNotExist(err) {
		log.Println("installing frontend dependencies...")
		installMgr := NewManager()
		if err := installMgr.Start(ctx, "npm-install", frontendDir, nil, l.detect.NPMPath, "ci"); err != nil {
			return fmt.Errorf("npm install: %w", err)
		}
		installMgr.WaitAll()
	}

	env := []string{
		"VULTURE_PROXY_TARGET=http://localhost:" + l.cfg.BackendPort,
		"VITE_LOCAL_MODE=true",
	}

	err := l.mgr.Start(ctx, "frontend", frontendDir, env,
		l.detect.NPMPath, "run", "dev", "--", "--port", l.cfg.FrontendPort,
	)
	if err != nil {
		return fmt.Errorf("start frontend: %w", err)
	}
	log.Printf("started frontend dev server on port %s", l.cfg.FrontendPort)
	return nil
}

func printBanner(cfg *Config) {
	fmt.Println(`
 _    __      ____
| |  / /_  __/ / /___  __________
| | / / / / / / __/ / / / ___/ _ \
| |/ / /_/ / / /_/ /_/ / /  /  __/
|___/\__,_/_/\__/\__,_/_/   \___/

  LOCAL DEVELOPMENT MODE`)
	fmt.Println()
	fmt.Printf("  Backend:   http://localhost:%s\n", cfg.BackendPort)
	fmt.Printf("  Frontend:  http://localhost:%s\n", cfg.FrontendPort)

	// Build agent port display from registry
	agentParts := make([]string, 0, len(config.AllAgents))
	for _, entry := range config.AllAgents {
		agentParts = append(agentParts, entry.Type+":"+cfg.AgentPorts[entry.Type])
	}
	fmt.Printf("  Agents:    %s\n", strings.Join(agentParts, "  "))

	fmt.Printf("  Data:      %s\n", cfg.DataDir)

	// Show LLM/embedding configuration
	if embURL := os.Getenv("VULTURE_EMBEDDING_URL"); embURL != "" {
		embModel := os.Getenv("VULTURE_EMBEDDING_MODEL")
		if embModel == "" {
			embModel = "text-embedding-3-small"
		}
		fmt.Printf("  Embeddings: %s (%s)\n", embModel, embURL)
	}
	if llmModel := os.Getenv("VULTURE_LLM_MODEL"); llmModel != "" {
		fmt.Printf("  LLM:       %s\n", llmModel)
	}

	fmt.Println()
	fmt.Println("  Press Ctrl+C to stop all services")
	fmt.Println()
}

// extraPythonPath returns additional PYTHONPATH entries for agents that
// depend on other agent packages. For example, the discover agent imports
// prove_agent.plugins, so it needs the prove agent directory on its path.
func extraPythonPath(agentsDir, agentType string) string {
	// Map of agent type → list of other agent directories it depends on
	deps := map[string][]string{
		"discover": {"prove"},
	}
	dirs, ok := deps[agentType]
	if !ok {
		return ""
	}
	var extra string
	for _, dir := range dirs {
		extra += ":" + filepath.Join(agentsDir, dir)
	}
	return extra
}
