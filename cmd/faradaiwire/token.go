package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
)

func executeToken(args []string, out, errOut io.Writer) int {
	if out == nil {
		out = os.Stdout
	}
	if errOut == nil {
		errOut = os.Stderr
	}

	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() { printTokenUsage(errOut) }
	cfgPath := fs.String("config", "", "Path to YAML configuration file")
	jsonOutput := fs.Bool("json", false, "Emit JSON formatted token metadata and Magic Link")
	hostOverride := fs.String("host", "", "Host name for Magic Link URL (defaults to localhost when bound to 0.0.0.0)")
	portOverride := fs.Int("port", 0, "Admin port override for Magic Link URL")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}

	cfg := loadConfigWithoutCreating(*cfgPath)
	if cfg == nil {
		cfg = &config.Config{}
	}

	keysPath := cfg.GetAPIKeysPath()
	ks, err := auth.NewFileKeyStore(keysPath)
	if err != nil {
		fmt.Fprintf(errOut, "Error: Failed to read keystore at %s: %v\n", keysPath, err)
		return 1
	}

	adminMeta := findActiveAdminKey(ks)
	if adminMeta == nil || strings.TrimSpace(adminMeta.RawKey) == "" {
		fmt.Fprintf(errOut, "No active Bootstrap Master Key found in %s. Start FaradAiWire ('faradaiwire run') first.\n", keysPath)
		return 1
	}

	scheme := "http"
	if cfg.AdminTLS.Enabled {
		scheme = "https"
	}
	host := strings.TrimSpace(*hostOverride)
	if host == "" {
		host = normalizePublicAdminHost(cfg.GetAdminHost())
	}
	port := cfg.GetAdminPort()
	if *portOverride > 0 {
		port = *portOverride
	}

	magicLink := fmt.Sprintf("%s://%s/admin/dashboard?token=%s", scheme, net.JoinHostPort(host, strconv.Itoa(port)), adminMeta.RawKey)

	if *jsonOutput {
		payload := map[string]string{
			"key_id":     adminMeta.ID,
			"name":       adminMeta.Name,
			"role":       adminMeta.Role,
			"agent_name": adminMeta.AgentName,
			"api_key":    adminMeta.RawKey,
			"magic_link": magicLink,
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(payload); err != nil {
			fmt.Fprintf(errOut, "Error: Failed to encode JSON output: %v\n", err)
			return 1
		}
		return 0
	}

	fmt.Fprintln(out, "\nFaradAiWire Bootstrap Master Key (Admin)")
	fmt.Fprintln(out, "========================================")
	fmt.Fprintf(out, "  Key ID      : %s\n", adminMeta.ID)
	fmt.Fprintf(out, "  Role / Scope: %s (%s)\n", adminMeta.Role, adminMeta.AgentName)
	fmt.Fprintf(out, "  API Key     : %s\n", adminMeta.RawKey)
	fmt.Fprintf(out, "  Magic Link  : %s\n", magicLink)
	if !cfg.IsStdioAllowed() && *portOverride <= 0 {
		fmt.Fprintf(out, "  Note        : %s\n", auth.TokenRecoveryPortHint(port))
	}
	fmt.Fprintln(out)
	return 0
}

func loadConfigWithoutCreating(explicitPath string) *config.Config {
	p := strings.TrimSpace(explicitPath)
	if p == "" {
		candidate := filepath.Join(config.DefaultFaradAiWireDir(), "config.yaml")
		if _, err := os.Stat(candidate); err == nil {
			p = candidate
		} else if _, err := os.Stat("config.yaml"); err == nil {
			p = "config.yaml"
		}
	}
	if p == "" {
		return nil
	}
	cfg, err := config.NewYAMLConfigProvider(p).Load()
	if err != nil {
		return nil
	}
	return cfg
}

func findActiveAdminKey(ks auth.KeyStore) *auth.KeyMetadata {
	if ks == nil {
		return nil
	}
	var candidates []*auth.KeyMetadata
	for _, k := range ks.ListKeys() {
		if k != nil && !k.Revoked && strings.EqualFold(k.Role, "Admin") && strings.TrimSpace(k.RawKey) != "" {
			candidates = append(candidates, k)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		if !candidates[i].CreatedAt.Equal(candidates[j].CreatedAt) {
			return candidates[i].CreatedAt.Before(candidates[j].CreatedAt)
		}
		return candidates[i].ID < candidates[j].ID
	})
	return candidates[0]
}

func normalizePublicAdminHost(host string) string {
	h := strings.TrimSpace(host)
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	switch h {
	case "", "0.0.0.0", "::":
		return "localhost"
	default:
		return h
	}
}
