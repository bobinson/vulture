package pluginregistry

import "testing"

func TestPluginContainerHost(t *testing.T) {
	cases := []struct {
		name      string
		localMode bool
		plugin    string
		want      string
	}{
		{"compose uses alias", false, "semgrep", "agent-semgrep"},
		{"compose sanitises slug", false, "My_Plugin", "agent-my-plugin"},
		{"local mode uses localhost", true, "semgrep", "localhost"},
		{"local mode ignores slug", true, "My_Plugin", "localhost"},
	}
	for _, c := range cases {
		if got := PluginContainerHost(c.localMode, c.plugin); got != c.want {
			t.Errorf("%s: PluginContainerHost(%v,%q)=%q want %q", c.name, c.localMode, c.plugin, got, c.want)
		}
	}
}

func TestContainerSourcePath(t *testing.T) {
	cases := []struct {
		name              string
		localMode, isCont bool
		in, want          string
	}{
		{"local container prefixes", true, true, "/home/user/src/vulture-gh", "/audit-inputs/home/user/src/vulture-gh"},
		{"local container git clone", true, true, "/tmp/vulture-sources/abc", "/audit-inputs/tmp/vulture-sources/abc"},
		{"local non-container unchanged", true, false, "/home/user/x", "/home/user/x"},
		{"compose container unchanged", false, true, "/audit-inputs/x", "/audit-inputs/x"},
		{"empty unchanged", true, true, "", ""},
	}
	for _, c := range cases {
		if got := ContainerSourcePath(c.localMode, c.isCont, c.in); got != c.want {
			t.Errorf("%s: ContainerSourcePath(%v,%v,%q)=%q want %q", c.name, c.localMode, c.isCont, c.in, got, c.want)
		}
	}
}
