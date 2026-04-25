package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// cmdAPIKey dispatches api-key subcommands: create, list, revoke.
func cmdAPIKey(apiURL string, args []string) {
	if len(args) == 0 {
		printAPIKeyUsage()
		os.Exit(1)
	}

	// Parse optional --api-key and --server from the remaining args.
	var apiKey, server string
	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--api-key":
			if i+1 < len(args) {
				apiKey = args[i+1]
				i++
			}
		case "--server":
			if i+1 < len(args) {
				server = args[i+1]
				i++
			}
		default:
			filtered = append(filtered, args[i])
		}
	}
	if server != "" {
		apiURL = server
	}
	token := resolveToken(apiKey, apiURL)

	if len(filtered) == 0 {
		printAPIKeyUsage()
		os.Exit(1)
	}

	sub := filtered[0]
	switch sub {
	case "create":
		if len(filtered) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: vulture api-key create <name>")
			os.Exit(1)
		}
		cmdAPIKeyCreate(apiURL, token, filtered[1])
	case "list":
		cmdAPIKeyList(apiURL, token)
	case "revoke":
		if len(filtered) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: vulture api-key revoke <id>")
			os.Exit(1)
		}
		cmdAPIKeyRevoke(apiURL, token, filtered[1])
	case "help", "--help", "-h":
		printAPIKeyUsage()
	default:
		fmt.Fprintf(os.Stderr, "  Error: unknown api-key subcommand %q\n\n", sub)
		printAPIKeyUsage()
		os.Exit(1)
	}
}

func printAPIKeyUsage() {
	fmt.Fprintf(os.Stderr, `Vulture API Key Management

Usage:
  vulture api-key create <name>         Create a new API key
  vulture api-key list                  List active API keys
  vulture api-key revoke <id>           Revoke an API key

Options:
  --api-key <key>                       Authenticate with an existing API key
  --server <url>                        Server URL override

Examples:
  vulture api-key create ci-github-actions
  vulture api-key list
  vulture api-key revoke abc123
`)
}

// apiKeyCreateResponse matches the backend's POST /api/api-keys response.
type apiKeyCreateResponse struct {
	ID        string `json:"id"`
	Prefix    string `json:"prefix"`
	Name      string `json:"name"`
	Key       string `json:"key"`
	CreatedAt string `json:"created_at"`
}

// apiKeyListItem matches a single entry from GET /api/api-keys.
type apiKeyListItem struct {
	ID         string  `json:"id"`
	Prefix     string  `json:"prefix"`
	Name       string  `json:"name"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at"`
}

func cmdAPIKeyCreate(apiURL, token, name string) {
	body, _ := json.Marshal(map[string]string{"name": name})
	result := apiPost[apiKeyCreateResponse](apiURL+"/api/api-keys", body, token)

	fmt.Printf("\n  API key created successfully.\n\n")
	fmt.Printf("  Name:   %s\n", result.Name)
	fmt.Printf("  ID:     %s\n", result.ID)
	fmt.Printf("  Prefix: %s\n", result.Prefix)
	fmt.Printf("  Key:    %s\n\n", result.Key)
	fmt.Fprintf(os.Stderr, "  WARNING: Save this key now. It will not be shown again.\n\n")
}

func cmdAPIKeyList(apiURL, token string) {
	keys := apiGet[[]apiKeyListItem](apiURL+"/api/api-keys", token)

	if len(keys) == 0 {
		fmt.Println("  No API keys found.")
		return
	}

	fmt.Println()
	fmt.Printf("  %-12s %-25s %-22s %s\n", "PREFIX", "NAME", "CREATED", "LAST USED")
	fmt.Println("  " + strings.Repeat("-", 75))
	for _, k := range keys {
		lastUsed := "never"
		if k.LastUsedAt != nil && *k.LastUsedAt != "" {
			lastUsed = *k.LastUsedAt
		}
		fmt.Printf("  %-12s %-25s %-22s %s\n", k.Prefix, k.Name, k.CreatedAt, lastUsed)
	}
	fmt.Println()
}

func cmdAPIKeyRevoke(apiURL, token, id string) {
	apiDelete(apiURL+"/api/api-keys/"+id, token)
	fmt.Printf("\n  API key %s revoked successfully.\n\n", id)
}
