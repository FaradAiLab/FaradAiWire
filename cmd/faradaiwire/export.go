package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/mcpconfig"
	"github.com/FaradAiLab/FaradAiWire/internal/mcpexport"
	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
)

type exportOptions struct {
	profile      string
	client       string
	scope        string
	out          string
	companionOut string
	adminURL     string
	configPath   string
}

func newExportHTTPClient() *http.Client {
	transport, ok := http.DefaultTransport.(*http.Transport)
	var cloned *http.Transport
	if ok && transport != nil {
		cloned = transport.Clone()
	} else {
		cloned = &http.Transport{}
	}
	if cloned.TLSClientConfig != nil {
		cloned.TLSClientConfig = cloned.TLSClientConfig.Clone()
	} else {
		cloned.TLSClientConfig = &tls.Config{}
	}
	if cloned.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		cloned.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	return &http.Client{
		Timeout:       15 * time.Second,
		Transport:     cloned,
		CheckRedirect: blockRedirects,
	}
}

func executeExport(args []string, stdout, stderr io.Writer) int {
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	if len(args) > 0 && isHelpArg(args[0]) {
		printExportUsage(stdout)
		return 0
	}

	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { printExportUsage(stderr) }

	profile := fs.String("profile", "", "Security Profile name to export")
	client := fs.String("client", "", "Target Client ID (claude-code, claude-desktop, cursor, cursor-workspace, windsurf, cline, roo-code, antigravity, generic)")
	scope := fs.String("scope", "", "Target scope (global or project)")
	outPath := fs.String("out", "", "Write primary MCP JSON to a brand-new file instead of stdout")
	companionOut := fs.String("companion-out", "", "Write optional companion snippet (e.g. Claude Code settings) to a brand-new file")
	adminURL := fs.String("admin-url", "", "Remote Admin API base URL (HTTPS required for non-loopback hosts)")
	cfgPath := fs.String("config", "", "Path to YAML configuration file")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}

	opts := exportOptions{
		profile:      strings.TrimSpace(*profile),
		client:       strings.TrimSpace(*client),
		scope:        strings.TrimSpace(*scope),
		out:          strings.TrimSpace(*outPath),
		companionOut: strings.TrimSpace(*companionOut),
		adminURL:     strings.TrimSpace(*adminURL),
		configPath:   strings.TrimSpace(*cfgPath),
	}

	if opts.profile == "" || opts.client == "" {
		fmt.Fprintln(stderr, "Error: both --profile and --client are required.")
		printExportUsage(stderr)
		return 1
	}
	if err := pathguard.ValidateSafeIdentifier(opts.profile); err != nil {
		fmt.Fprintf(stderr, "Error: invalid profile name %q: %v\n", opts.profile, err)
		return 1
	}

	clientOS := currentExportClientOS()
	if _, _, _, err := mcpexport.ResolveTargetMeta(opts.client, opts.scope, clientOS); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	var result *mcpexport.ExportResult
	var err error
	if opts.adminURL != "" {
		result, err = runRemoteExport(opts, clientOS)
	} else {
		result, err = runOfflineExport(opts, clientOS)
	}
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	primaryJSON, err := json.MarshalIndent(result.Config, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "Error: marshal exported config: %v\n", err)
		return 1
	}
	primaryJSON = append(primaryJSON, '\n')

	if opts.out != "" {
		if err := writeNewExportFile(opts.out, primaryJSON, runtime.GOOS); err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
	} else {
		if _, err := stdout.Write(primaryJSON); err != nil {
			fmt.Fprintf(stderr, "Error: write stdout: %v\n", err)
			return 1
		}
	}

	if len(result.CompanionFiles) > 0 {
		if opts.companionOut != "" {
			compBytes, err := json.MarshalIndent(result.CompanionFiles[0].Content, "", "  ")
			if err != nil {
				fmt.Fprintf(stderr, "Error: marshal companion config: %v\n", err)
				return 1
			}
			compBytes = append(compBytes, '\n')
			if err := writeNewExportFile(opts.companionOut, compBytes, runtime.GOOS); err != nil {
				fmt.Fprintf(stderr, "Error: %v\n", err)
				return 1
			}
		} else {
			fmt.Fprintf(stderr, "[info] Companion file (%s) was generated; pass --companion-out <new-file> to save it separately.\n", result.CompanionFiles[0].PathHint)
		}
	}

	for _, w := range result.Warnings {
		if w.Server != "" {
			fmt.Fprintf(stderr, "[%s] %s (%s): %s\n", w.Severity, w.Code, w.Server, w.Message)
		} else {
			fmt.Fprintf(stderr, "[%s] %s: %s\n", w.Severity, w.Code, w.Message)
		}
	}
	return 0
}

func currentExportClientOS() string {
	switch runtime.GOOS {
	case "darwin":
		return mcpexport.OSDarwin
	case "windows":
		return mcpexport.OSWindows
	default:
		return mcpexport.OSLinux
	}
}

// runOfflineExport reads strictly from the active config's agents and protocols directories,
// bypassing agent.NewFSRepository's silent ./agents and /etc/faradaiwire/agents fallbacks.
func runOfflineExport(opts exportOptions, clientOS string) (*mcpexport.ExportResult, error) {
	cfg := loadConfigWithoutCreating(opts.configPath)
	if cfg == nil {
		cfg = &config.Config{}
	}

	agentsDir := cfg.GetAgentsDir()
	agentDir, err := pathguard.ResolveSandboxedPath(agentsDir, opts.profile)
	if err != nil {
		return nil, fmt.Errorf("resolve profile path: %w", err)
	}

	route, err := readStrictAgentConfig(agentDir)
	if err != nil {
		return nil, fmt.Errorf("load profile %q from %s: %w", opts.profile, agentsDir, err)
	}
	manifest := readStrictAgentManifest(agentDir)

	var lookup mcpexport.ProtocolLookup
	if pStore, err := protocol.NewFSStore(cfg.GetProtocolsDir()); err == nil && pStore != nil {
		lookup = func(id string) (*protocol.Protocol, bool) {
			p, err := pStore.Get(id)
			if err != nil || p == nil {
				return nil, false
			}
			return p, true
		}
	}

	return mcpexport.Export(context.Background(), mcpexport.ExportRequest{
		Client:   opts.client,
		Scope:    opts.scope,
		ClientOS: clientOS,
		Route:    route,
		Manifest: manifest,
		Lookup:   lookup,
	})
}

func readStrictAgentConfig(agentDir string) (*agent.RouteConfig, error) {
	candidates := []string{
		filepath.Join(agentDir, "current", "config.json"),
		filepath.Join(agentDir, "config.json"),
	}
	var lastErr error
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			lastErr = err
			continue
		}
		var cfg agent.RouteConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		return &cfg, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, os.ErrNotExist
}

func readStrictAgentManifest(agentDir string) []agent.ToolMetadata {
	candidates := []string{
		filepath.Join(agentDir, "current", "tools_manifest.json"),
		filepath.Join(agentDir, "tools_manifest.json"),
	}
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var tools []agent.ToolMetadata
		if err := json.Unmarshal(data, &tools); err == nil {
			return tools
		}
	}
	return nil
}

func runRemoteExport(opts exportOptions, clientOS string) (*mcpexport.ExportResult, error) {
	baseURL := strings.TrimRight(opts.adminURL, "/")
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid --admin-url %q", opts.adminURL)
	}

	scheme := strings.ToLower(parsed.Scheme)
	isLoopback := isLoopbackHost(parsed.Hostname())
	if scheme != "https" && !(scheme == "http" && isLoopback) {
		return nil, fmt.Errorf("refusing insecure plaintext http:// for non-loopback --admin-url %q; use https://", opts.adminURL)
	}

	reqBody, err := json.Marshal(map[string]string{
		"client":    opts.client,
		"scope":     opts.scope,
		"client_os": clientOS,
	})
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/admin/agents/%s/export", baseURL, url.PathEscape(opts.profile))
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if tok := resolveExportBearerToken(isLoopback, opts.configPath); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := newExportHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("remote export failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result mcpexport.ExportResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &result, nil
}

func resolveExportBearerToken(allowLocalKeystore bool, configPath string) string {
	if tok := strings.TrimSpace(os.Getenv("ADMIN_API_KEY")); tok != "" {
		return tok
	}
	if !allowLocalKeystore {
		return ""
	}
	cfg := loadConfigWithoutCreating(configPath)
	if cfg == nil {
		cfg = &config.Config{}
	}
	keysPath := cfg.GetAPIKeysPath()
	if _, err := os.Stat(keysPath); err != nil {
		return ""
	}
	ks, err := auth.NewFileKeyStore(keysPath)
	if err != nil {
		return ""
	}
	if adminMeta := findActiveAdminKey(ks); adminMeta != nil {
		return strings.TrimSpace(adminMeta.RawKey)
	}
	return ""
}

// writeNewExportFile refuses any protected client config path (via deepest-existing-ancestor symlink
// resolution + case-insensitive comparison on darwin/windows) and writes exclusively with O_EXCL (0600).
func writeNewExportFile(targetPath string, data []byte, targetOS string) error {
	resolved, err := resolveCanonicalWithMissingTail(targetPath)
	if err != nil {
		return fmt.Errorf("resolve output path %q: %w", targetPath, err)
	}

	if isProtectedClientConfigPath(resolved, targetOS) {
		return fmt.Errorf("refusing to write to protected target client config path %q", targetPath)
	}

	parent := filepath.Dir(resolved)
	if err := os.MkdirAll(parent, 0750); err != nil {
		return fmt.Errorf("create output directory %q: %w", parent, err)
	}

	// Re-resolve after directory creation to narrow symlink TOCTOU races before O_EXCL open.
	resolved, err = resolveCanonicalWithMissingTail(targetPath)
	if err != nil {
		return fmt.Errorf("resolve output path %q: %w", targetPath, err)
	}
	if isProtectedClientConfigPath(resolved, targetOS) {
		return fmt.Errorf("refusing to write to protected target client config path %q", targetPath)
	}

	f, err := os.OpenFile(resolved, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("refusing to overwrite existing file %q (specify a new path)", targetPath)
		}
		return fmt.Errorf("open output file %q: %w", targetPath, err)
	}

	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		_ = os.Remove(resolved)
		return fmt.Errorf("write output file %q: %w", targetPath, writeErr)
	}
	if closeErr != nil {
		_ = os.Remove(resolved)
		return fmt.Errorf("close output file %q: %w", targetPath, closeErr)
	}
	return nil
}

// resolveCanonicalWithMissingTail resolves symlinks on the deepest existing ancestor directory
// and re-appends non-existent trailing path segments cleanly.
func resolveCanonicalWithMissingTail(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	cleaned := filepath.Clean(abs)

	var tail []string
	cur := cleaned
	for {
		realPath, err := filepath.EvalSymlinks(cur)
		if err == nil {
			for i := len(tail) - 1; i >= 0; i-- {
				realPath = filepath.Join(realPath, tail[i])
			}
			return filepath.Clean(realPath), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return cleaned, nil
		}
		tail = append(tail, filepath.Base(cur))
		cur = parent
	}
}

func isProtectedClientConfigPath(resolvedPath, targetOS string) bool {
	norm := func(s string) string {
		s = filepath.ToSlash(filepath.Clean(s))
		if targetOS == "darwin" || targetOS == "windows" {
			return strings.ToLower(s)
		}
		return s
	}

	candidate := norm(resolvedPath)

	protectedSuffixes := []string{
		"/.mcp.json",
		"/.cursor/mcp.json",
		"/.roo/mcp.json",
		"/.agents/mcp_config.json",
		"/.claude/settings.json",
		"/.claude/settings.local.json",
	}
	for _, suf := range protectedSuffixes {
		if strings.HasSuffix(candidate, norm(suf)) {
			return true
		}
	}

	var protectedExact []string
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		protectedExact = append(protectedExact,
			filepath.Join(home, ".claude.json"),
			filepath.Join(home, ".claude", "settings.json"),
			filepath.Join(home, ".cline", "data", "settings", "cline_mcp_settings.json"),
			filepath.Join(home, ".gemini", "antigravity", "mcp_config.json"),
			filepath.Join(home, ".gemini", "config", "mcp_config.json"),
			filepath.Join(home, ".cursor", "mcp.json"),
			filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"),
		)
	}
	if p := strings.TrimSpace(os.Getenv("CLINE_MCP_SETTINGS_PATH")); p != "" {
		protectedExact = append(protectedExact, p)
	}
	if d := strings.TrimSpace(os.Getenv("CLINE_DATA_DIR")); d != "" {
		protectedExact = append(protectedExact, filepath.Join(d, "settings", "cline_mcp_settings.json"))
	}

	// Include enterprise managed paths and existing adapter-resolved global client paths.
	protectedExact = append(protectedExact,
		"/Library/Application Support/ClaudeCode/managed-mcp.json",
		"/Library/Application Support/ClaudeCode/managed-settings.json",
		"/etc/claude-code/managed-mcp.json",
		"/etc/claude-code/managed-settings.json",
		`C:\Program Files\ClaudeCode\managed-mcp.json`,
		`C:\Program Files\ClaudeCode\managed-settings.json`,
	)

	adapters := []mcpconfig.ClientAdapter{
		mcpconfig.NewClaudeCodeAdapter(),
		mcpconfig.NewClaudeDesktopAdapter(),
		mcpconfig.NewCursorAdapter(),
		mcpconfig.NewWindsurfAdapter(),
		mcpconfig.NewClineAdapter(),
		mcpconfig.NewRooCodeAdapter(),
		mcpconfig.NewAntigravityAdapter(),
	}
	for _, ad := range adapters {
		if p, err := ad.ConfigPath(); err == nil && p != "" {
			protectedExact = append(protectedExact, p)
		}
	}

	for _, exact := range protectedExact {
		if rExact, err := resolveCanonicalWithMissingTail(exact); err == nil {
			if candidate == norm(rExact) {
				return true
			}
		}
		if candidate == norm(exact) {
			return true
		}
	}

	return false
}
