package service

import "testing"

func TestTargetPath(t *testing.T) {
	sub := TargetIdentity{Key: "marker:x", Root: "/r", Offset: ".vscode"}
	root := TargetIdentity{Key: "marker:x", Root: "/r"}
	for _, tc := range []struct {
		name     string
		target   TargetIdentity
		reported string
		want     string
	}{
		{"sub-path relative gains the offset", sub, "tasks.json", ".vscode/tasks.json"},
		{"sub-path dot-relative is normalised", sub, "./tasks.json", ".vscode/tasks.json"},
		{"root relative is unchanged", root, ".vscode/tasks.json", ".vscode/tasks.json"},
		{"absolute is unchanged", sub, "/r/.vscode/tasks.json", "/r/.vscode/tasks.json"},
		{"empty stays empty", sub, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := targetPath(tc.target, tc.reported); got != tc.want {
				t.Fatalf("targetPath(%q) = %q, want %q", tc.reported, got, tc.want)
			}
		})
	}
}

func TestAgentPath(t *testing.T) {
	sub := TargetIdentity{Key: "marker:x", Root: "/r", Offset: ".vscode"}
	root := TargetIdentity{Key: "marker:x", Root: "/r"}
	for _, tc := range []struct {
		name   string
		target TargetIdentity
		stored string
		want   string
		inScan bool
	}{
		{"under the offset loses it", sub, ".vscode/tasks.json", "tasks.json", true},
		{"the offset directory itself", sub, ".vscode", "", true},
		{"outside the sub-tree is not requested", sub, "src/server.js", "", false},
		{"a sibling sharing the prefix is outside", sub, ".vscode-old/tasks.json", "", false},
		{"root scan is unchanged", root, ".vscode/tasks.json", ".vscode/tasks.json", true},
		{"absolute is unchanged", sub, "/r/src/server.js", "/r/src/server.js", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := agentPath(tc.target, tc.stored)
			if got != tc.want || ok != tc.inScan {
				t.Fatalf("agentPath(%q) = (%q, %v), want (%q, %v)", tc.stored, got, ok, tc.want, tc.inScan)
			}
		})
	}
}
