package config

import "testing"

func TestBrokerEnabled_DerivesFromUseLLM(t *testing.T) {
	cases := []struct {
		name, broker, useLLM string
		want                 bool
	}{
		{"nothing set", "", "", false},
		{"llm on, broker unset -> on (the fix)", "", "true", true},
		{"llm on, broker explicit off -> off (override wins)", "off", "true", false},
		{"llm off, broker explicit on -> on", "on", "", true},
		{"llm on, broker explicit on -> on", "on", "true", true},
		{"skills-only -> off", "", "false", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			get := func(k string) string {
				switch k {
				case "VULTURE_LLM_BROKER":
					return c.broker
				case "VULTURE_USE_LLM":
					return c.useLLM
				}
				return ""
			}
			if got := BrokerEnabled(get); got != c.want {
				t.Fatalf("BrokerEnabled(broker=%q,useLLM=%q) = %v, want %v", c.broker, c.useLLM, got, c.want)
			}
		})
	}
}

func TestLoadBrokerConfig_OnByDefaultWhenLLMUsed(t *testing.T) {
	t.Setenv("VULTURE_USE_LLM", "true")
	t.Setenv("VULTURE_LLM_BROKER", "")
	bc := loadBrokerConfig(iniValues{})
	if !bc.Enabled {
		t.Fatal("broker should be enabled by default when VULTURE_USE_LLM=true and VULTURE_LLM_BROKER unset")
	}
	if bc.URL == "" {
		t.Fatal("broker URL should be derived from the listen address when unset")
	}
}

func TestLoadBrokerConfig_DerivesProviderBaseURLFromOpenAIBase(t *testing.T) {
	t.Setenv("VULTURE_USE_LLM", "true")
	t.Setenv("VULTURE_LLM_BROKER", "")
	t.Setenv("OPENAI_BASE_URL", "http://127.0.0.1:1234/v1") // local LM Studio
	t.Setenv("VULTURE_LLM_BROKER_PROVIDER_BASE_URL", "")
	t.Setenv("VULTURE_LLM_BROKER_ALLOW_LOCAL_EGRESS", "")
	bc := loadBrokerConfig(iniValues{})
	if bc.ProviderBaseURL != "http://127.0.0.1:1234/v1" {
		t.Fatalf("auto-enabled broker should route to the existing OPENAI_BASE_URL, got %q", bc.ProviderBaseURL)
	}
	if bc.Provider != "openai-compatible" {
		t.Fatalf("provider should be openai-compatible for a derived custom endpoint, got %q", bc.Provider)
	}
	if !bc.AllowLocalEgress {
		t.Fatal("auto-enabled broker to a loopback endpoint should allow local egress so the local LLM stays reachable")
	}
}

func TestLoadBrokerConfig_SkillsOnlyOff(t *testing.T) {
	t.Setenv("VULTURE_USE_LLM", "")
	t.Setenv("VULTURE_LLM_BROKER", "")
	if loadBrokerConfig(iniValues{}).Enabled {
		t.Fatal("broker must stay off in skills-only mode (Mode A default unchanged)")
	}
}

func TestIsLocalURL(t *testing.T) {
	for _, u := range []string{"http://127.0.0.1:1234/v1", "http://localhost/v1", "http://192.168.1.5:11434", "http://10.0.0.2/v1", "http://172.16.0.1/v1", "https://[::1]:8000"} {
		if !isLocalURL(u) {
			t.Errorf("isLocalURL(%q) = false, want true", u)
		}
	}
	for _, u := range []string{"https://api.openai.com/v1", "http://172.32.0.1/v1", "https://gateway.example.com"} {
		if isLocalURL(u) {
			t.Errorf("isLocalURL(%q) = true, want false", u)
		}
	}
}
