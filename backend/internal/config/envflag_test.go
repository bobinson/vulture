package config

import (
	"os"
	"testing"
)

func TestEnvFlag(t *testing.T) {
	const k = "VULTURE_ENVFLAG_TEST"
	cases := []envFlagCase{
		{"true", false, true, false}, {"1", false, true, false}, {"YES", false, true, false}, {" On ", false, true, false},
		{"false", true, false, false}, {"0", true, false, false}, {"NO", true, false, false}, {" Off ", true, false, false},
		{"", true, true, false}, {"  ", true, true, false}, {"maybe", true, true, false},
		{"", false, false, false}, {"maybe", false, false, false},
		{"", true, true, true}, {"", false, false, true},
	}
	for _, c := range cases {
		setEnvFlagCase(t, k, c)
		if got := EnvFlag(k, c.def); got != c.want {
			t.Errorf("EnvFlag(%q, %v, unset=%v) = %v, want %v", c.value, c.def, c.unset, got, c.want)
		}
	}
}

// envFlagCase is one EnvFlag input: a value (or an unset variable) and a default.
type envFlagCase struct {
	value string
	def   bool
	want  bool
	unset bool
}

// setEnvFlagCase sets k to the case's value, or unsets it. t.Setenv registers
// the cleanup that restores the prior state either way.
func setEnvFlagCase(t *testing.T, k string, c envFlagCase) {
	t.Helper()
	t.Setenv(k, c.value)
	if !c.unset {
		return
	}
	if err := os.Unsetenv(k); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
}
