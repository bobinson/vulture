package localdev

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// Config holds local development launch configuration.
type Config struct {
	ProjectRoot string
	DataDir     string
	BackendPort string
	FrontendPort string
	AgentPorts  map[string]string // agent_type -> port
}

// DefaultConfig returns default local development configuration.
func DefaultConfig(projectRoot string) *Config {
	dataDir, _ := DefaultDataDir()
	return &Config{
		ProjectRoot:  projectRoot,
		DataDir:      dataDir,
		BackendPort:  "8080",
		FrontendPort: "3001",
		AgentPorts: map[string]string{
			"chaos": "8001",
			"owasp": "8002",
			"soc2":  "8003",
			"cwe":   "8004",
		},
	}
}

// Launcher orchestrates all local development processes.
type Launcher struct {
	cfg     *Config
	mgr     *Manager
	detect  *Detect
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
	det, err := CheckPrereqs(l.cfg.ProjectRoot)
	if err != nil {
		return fmt.Errorf("prerequisites: %w", err)
	}
	l.detect = det

	// 0. Set up Ollama if available (auto-pull embedding + LLM models)
	// Must run before printBanner so env vars are set for banner display.
	l.setupOllama(ctx)

	printBanner(l.cfg)

	// 1. Install Python agent dependencies if needed
	if err := l.installAgentDeps(ctx); err != nil {
		log.Printf("warning: agent deps install: %v", err)
	}

	// 2. Start Python agents
	if err := l.startAgents(ctx); err != nil {
		return fmt.Errorf("start agents: %w", err)
	}

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

	if hasCloudKey && !hasExplicitModel {
		// User has cloud key, don't override their setup
		log.Println("  Using cloud API (OPENAI_API_KEY set)")
		return
	}

	// Auto-pull embedding model
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

func (l *Launcher) installAgentDeps(ctx context.Context) error {
	agentsDir := filepath.Join(l.cfg.ProjectRoot, "agents")
	sharedDir := filepath.Join(agentsDir, "shared")

	// Install shared package in editable mode
	log.Println("installing Python agent dependencies...")
	cmd := fmt.Sprintf("%s -m pip install -e %s -q 2>/dev/null || %s -m pip install -e %s -q --break-system-packages 2>/dev/null", l.detect.PythonPath, sharedDir, l.detect.PythonPath, sharedDir)
	err := l.mgr.Start(ctx, "pip-shared", agentsDir,
		[]string{},
		"sh", "-c", cmd,
	)
	if err != nil {
		return fmt.Errorf("install shared: %w", err)
	}

	for _, agent := range []string{"chaos_engineering", "owasp", "soc2"} {
		agentDir := filepath.Join(agentsDir, agent)
		if _, err := os.Stat(agentDir); os.IsNotExist(err) {
			continue
		}
		installCmd := fmt.Sprintf("%s -m pip install -e %s -q 2>/dev/null || %s -m pip install -e %s -q --break-system-packages 2>/dev/null", l.detect.PythonPath, agentDir, l.detect.PythonPath, agentDir)
		err := l.mgr.Start(ctx, "pip-"+agent, agentsDir,
			[]string{},
			"sh", "-c", installCmd,
		)
		if err != nil {
			log.Printf("warning: install %s: %v", agent, err)
		}
	}
	return nil
}

func (l *Launcher) startAgents(ctx context.Context) error {
	agentsDir := filepath.Join(l.cfg.ProjectRoot, "agents")

	agents := []struct {
		name    string
		module  string
		port    string
		dir     string
	}{
		{"chaos", "chaos_agent.main:app", l.cfg.AgentPorts["chaos"], filepath.Join(agentsDir, "chaos_engineering")},
		{"owasp", "owasp_agent.main:app", l.cfg.AgentPorts["owasp"], filepath.Join(agentsDir, "owasp")},
		{"soc2", "soc2_agent.main:app", l.cfg.AgentPorts["soc2"], filepath.Join(agentsDir, "soc2")},
		{"cwe", "cwe_agent.main:app", l.cfg.AgentPorts["cwe"], filepath.Join(agentsDir, "cwe")},
	}

	for _, a := range agents {
		if _, err := os.Stat(a.dir); os.IsNotExist(err) {
			log.Printf("skipping agent %s: directory not found", a.name)
			continue
		}
		env := []string{
			"VULTURE_AGENT_PORT=" + a.port,
			"VULTURE_BACKEND_URL=http://localhost:" + l.cfg.BackendPort,
			"PYTHONPATH=" + agentsDir + "/shared:" + a.dir,
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
		// Disable OpenAI Agents SDK tracing (avoids 400 errors from unsupported fields).
		env = append(env, "OPENAI_AGENTS_DISABLE_TRACING=1")

		err := l.mgr.Start(ctx, "agent-"+a.name, a.dir, env,
			l.detect.PythonPath, "-m", "uvicorn", a.module,
			"--host", "0.0.0.0", "--port", a.port,
		)
		if err != nil {
			return fmt.Errorf("start agent %s: %w", a.name, err)
		}
		log.Printf("started agent-%s on port %s", a.name, a.port)
	}
	return nil
}

func (l *Launcher) startBackend(ctx context.Context) error {
	dbPath := filepath.Join(l.cfg.DataDir, "vulture.db")
	env := []string{
		"VULTURE_PORT=" + l.cfg.BackendPort,
		"VULTURE_DB_PATH=" + dbPath,
		"VULTURE_DB_DSN=",
		"VULTURE_LOCAL_MODE=true",
		"VULTURE_AGENT_CHAOS_URL=http://localhost:" + l.cfg.AgentPorts["chaos"],
		"VULTURE_AGENT_OWASP_URL=http://localhost:" + l.cfg.AgentPorts["owasp"],
		"VULTURE_AGENT_SOC2_URL=http://localhost:" + l.cfg.AgentPorts["soc2"],
		"VULTURE_AGENT_CWE_URL=http://localhost:" + l.cfg.AgentPorts["cwe"],
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

	backendDir := filepath.Join(l.cfg.ProjectRoot, "backend")
	binPath := filepath.Join(backendDir, "bin", "vulture")

	// Build if binary doesn't exist
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		log.Println("building backend binary...")
		buildCmd := fmt.Sprintf("cd %s && %s build -o bin/vulture ./cmd/vulture/", backendDir, l.detect.GoPath)
		buildProc := NewManager()
		if err := buildProc.Start(ctx, "go-build", backendDir, nil, "sh", "-c", buildCmd); err != nil {
			return fmt.Errorf("build backend: %w", err)
		}
		buildProc.WaitAll()
	}

	err := l.mgr.Start(ctx, "backend", backendDir, env, binPath)
	if err != nil {
		return fmt.Errorf("start backend: %w", err)
	}
	log.Printf("started backend on port %s (SQLite: %s)", l.cfg.BackendPort, dbPath)
	return nil
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
		"VITE_API_URL=http://localhost:" + l.cfg.BackendPort,
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
	fmt.Printf("  Agents:    chaos:%s  owasp:%s  soc2:%s  cwe:%s\n",
		cfg.AgentPorts["chaos"], cfg.AgentPorts["owasp"], cfg.AgentPorts["soc2"], cfg.AgentPorts["cwe"])
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
