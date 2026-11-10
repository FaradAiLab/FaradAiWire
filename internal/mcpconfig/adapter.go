package mcpconfig

// ClientID identifies a supported developer IDE or client application.
type ClientID string

const (
	ClientClaudeDesktop   ClientID = "claude-desktop"
	ClientCursor          ClientID = "cursor"
	ClientCursorWorkspace ClientID = "cursor-workspace"
	ClientWindsurf        ClientID = "windsurf"
	ClientAntigravity     ClientID = "antigravity"
	ClientClaudeCode      ClientID = "claude-code"
	ClientCline           ClientID = "cline"
	ClientRooCode         ClientID = "roo-code"
)

// DiscoveredServer represents an MCP server definition discovered from a client IDE configuration.
type DiscoveredServer struct {
	ClientID        ClientID          `json:"client_id"`
	ClientName      string            `json:"client_name"`
	Name            string            `json:"name"`
	Command         string            `json:"command"`
	Args            []string          `json:"args"`
	Env             map[string]string `json:"env,omitempty"`
	URL             string            `json:"url,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	MatchedPresetID string            `json:"matched_preset_id,omitempty"`
	PresetTitle     string            `json:"preset_title,omitempty"`
}

// ClientAdapter abstracts configuration discovery, extraction, and safe mutation across different IDEs.
type ClientAdapter interface {
	// ID returns the unique canonical identifier of the client.
	ID() ClientID

	// DisplayName returns the human-readable name of the client application.
	DisplayName() string

	// ConfigPath returns the resolved filesystem path to the client's configuration file.
	ConfigPath() (string, error)

	// Detect returns true if the client configuration file exists on the current host.
	Detect() bool

	// ReadServers parses the client configuration and extracts all defined MCP servers.
	ReadServers() ([]DiscoveredServer, error)

	// ApplyGatewayConfig mutates the client configuration by substituting adopted servers
	// with a single FaradAiWire gateway connection under mcpServers.
	ApplyGatewayConfig(profileName string, adoptedServerNames []string) error

	// RestoreBackup restores the client configuration file from a specified backup path.
	RestoreBackup(backupPath string) error
}
