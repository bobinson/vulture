package localdev

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectModeInstall(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "VERSION"), []byte("v1.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VULTURE_HOME", home)
	if got := DetectMode(); got != ModeInstall {
		t.Fatalf("DetectMode() = %v, want ModeInstall", got)
	}
}

func TestDetectModeDevWithoutVersion(t *testing.T) {
	home := t.TempDir()
	t.Setenv("VULTURE_HOME", home)
	if got := DetectMode(); got != ModeDev {
		t.Fatalf("DetectMode() = %v, want ModeDev", got)
	}
}

func TestDetectModeDevWhenVersionIsDir(t *testing.T) {
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, "VERSION"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VULTURE_HOME", home)
	if got := DetectMode(); got != ModeDev {
		t.Fatalf("DetectMode() with VERSION as dir = %v, want ModeDev", got)
	}
}

func TestResolveHomeFromEnv(t *testing.T) {
	t.Setenv("VULTURE_HOME", "/opt/vulture")
	if got := ResolveHome(); got != "/opt/vulture" {
		t.Fatalf("ResolveHome() = %q, want /opt/vulture", got)
	}
}

func TestResolveHomeFromUserHome(t *testing.T) {
	t.Setenv("VULTURE_HOME", "")
	got := ResolveHome()
	if got == "" {
		t.Fatal("ResolveHome() returned empty; expected ~/.vulture or similar")
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("ResolveHome() = %q, want absolute path", got)
	}
}

func TestRuntimeRootInstall(t *testing.T) {
	t.Setenv("VULTURE_HOME", "/opt/vulture")
	got := RuntimeRoot(ModeInstall, "/ignored")
	want := "/opt/vulture/runtime"
	if got != want {
		t.Fatalf("RuntimeRoot(install) = %q, want %q", got, want)
	}
}

func TestRuntimeRootDev(t *testing.T) {
	t.Setenv("VULTURE_HOME", "/opt/vulture")
	got := RuntimeRoot(ModeDev, "/src/vulture")
	want := "/src/vulture"
	if got != want {
		t.Fatalf("RuntimeRoot(dev) = %q, want %q", got, want)
	}
}

func TestDataDirInstall(t *testing.T) {
	t.Setenv("VULTURE_HOME", "/opt/vulture")
	got := DataDir(ModeInstall, "/ignored")
	want := "/opt/vulture/data"
	if got != want {
		t.Fatalf("DataDir(install) = %q, want %q", got, want)
	}
}

func TestConfigDirInstall(t *testing.T) {
	t.Setenv("VULTURE_HOME", "/opt/vulture")
	got := ConfigDir(ModeInstall, "/ignored")
	want := "/opt/vulture/config"
	if got != want {
		t.Fatalf("ConfigDir(install) = %q, want %q", got, want)
	}
}

func TestPythonBinInstall(t *testing.T) {
	t.Setenv("VULTURE_HOME", "/opt/vulture")
	got := PythonBin(ModeInstall)
	want := "/opt/vulture/runtime/python/bin/python3.12"
	if got != want {
		t.Fatalf("PythonBin(install) = %q, want %q", got, want)
	}
}

func TestPythonBinDev(t *testing.T) {
	if got := PythonBin(ModeDev); got != "" {
		t.Fatalf("PythonBin(dev) = %q, want empty", got)
	}
}

func TestAgentsRootInstall(t *testing.T) {
	t.Setenv("VULTURE_HOME", "/opt/vulture")
	got := AgentsRoot(ModeInstall, "/ignored")
	want := "/opt/vulture/runtime/agents"
	if got != want {
		t.Fatalf("AgentsRoot(install) = %q, want %q", got, want)
	}
}

func TestModeString(t *testing.T) {
	cases := []struct {
		mode Mode
		want string
	}{
		{ModeDev, "dev"},
		{ModeInstall, "install"},
	}
	for _, tc := range cases {
		if got := tc.mode.String(); got != tc.want {
			t.Errorf("Mode(%d).String() = %q, want %q", tc.mode, got, tc.want)
		}
	}
}
