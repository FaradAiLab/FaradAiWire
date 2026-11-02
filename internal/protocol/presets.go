package protocol

// PresetMetadata represents a pre-configured, industry-standard MCP template for quick installation.
type PresetMetadata struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Category        string   `json:"category"` // "devops", "data", "web", "productivity", "memory"
	Type            string   `json:"type"`     // "stdio", "sse", "http"
	Command         string   `json:"command,omitempty"`
	Args            []string `json:"args,omitempty"`
	URL             string   `json:"url,omitempty"`
	EnvRequirements []string `json:"env_requirements,omitempty"`
	Icon            string   `json:"icon,omitempty"`
	DocURL          string   `json:"doc_url,omitempty"`
}

// GetPresets returns the curated catalog of top 20 industry-standard MCP presets.
func GetPresets() []PresetMetadata {
	return []PresetMetadata{
		// --- 🛠️ DEVOPS & CODE ---
		{
			ID:              "context7",
			Name:            "Context7 Live Docs & Code Context",
			Description:     "Real-time, version-specific library documentation and code snippets to eliminate LLM hallucinations.",
			Category:        "devops",
			Type:            "http",
			URL:             "https://mcp.context7.com/mcp",
			EnvRequirements: []string{"CONTEXT7_API_KEY"},
			Icon:            "book-open",
			DocURL:          "https://context7.com",
		},
		{
			ID:              "github",
			Name:            "GitHub Workspace",
			Description:     "Inspect repositories, file contents, pull requests, issues, and commit histories via official GitHub MCP.",
			Category:        "devops",
			Type:            "stdio",
			Command:         "npx",
			Args:            []string{"-y", "@modelcontextprotocol/server-github"},
			EnvRequirements: []string{"GITHUB_PERSONAL_ACCESS_TOKEN"},
			Icon:            "github",
			DocURL:          "https://github.com/modelcontextprotocol/servers/tree/main/src/github",
		},
		{
			ID:          "git",
			Name:        "Local Git Repository",
			Description: "Perform local git commands, branch inspections, commit tracking, and diff generation.",
			Category:    "devops",
			Type:        "stdio",
			Command:     "uvx",
			Args:        []string{"mcp-server-git"},
			Icon:        "git-branch",
			DocURL:      "https://github.com/modelcontextprotocol/servers/tree/main/src/git",
		},
		{
			ID:          "docker",
			Name:        "Docker Daemon",
			Description: "Control local containers, inspect running services, pull images, and monitor build logs.",
			Category:    "devops",
			Type:        "stdio",
			Command:     "docker-mcp",
			Args:        []string{},
			Icon:        "container",
			DocURL:      "https://github.com/modelcontextprotocol/servers",
		},
		{
			ID:          "kubernetes",
			Name:        "Kubernetes Cluster",
			Description: "Inspect pods, services, deployments, ingress rules, and cluster events with kubectl integration.",
			Category:    "devops",
			Type:        "stdio",
			Command:     "kubectl-mcp",
			Args:        []string{},
			Icon:        "server",
			DocURL:      "https://github.com/modelcontextprotocol/servers",
		},
		{
			ID:              "sentry",
			Name:            "Sentry Error & Performance",
			Description:     "Query production stack traces, issue frequencies, error trends, and release telemetry.",
			Category:        "devops",
			Type:        "stdio",
			Command:         "mcp-sentry",
			Args:            []string{},
			EnvRequirements: []string{"SENTRY_AUTH_TOKEN"},
			Icon:            "alert-triangle",
			DocURL:          "https://sentry.io",
		},

		// --- 💾 DATA & DATABASES ---
		{
			ID:              "postgres",
			Name:            "PostgreSQL Database",
			Description:     "Read schemas, execute analytical queries, and inspect relations with row-level safety guardrails.",
			Category:        "data",
			Type:            "stdio",
			Command:         "npx",
			Args:            []string{"-y", "@modelcontextprotocol/server-postgres"},
			EnvRequirements: []string{"POSTGRES_URL"},
			Icon:            "database",
			DocURL:          "https://github.com/modelcontextprotocol/servers/tree/main/src/postgres",
		},
		{
			ID:          "sqlite",
			Name:        "SQLite Database",
			Description: "Fast embedded SQL database inspection and table querying for local application data.",
			Category:    "data",
			Type:        "stdio",
			Command:     "uvx",
			Args:        []string{"mcp-server-sqlite", "--db-path", "app.db"},
			Icon:        "hard-drive",
			DocURL:      "https://github.com/modelcontextprotocol/servers/tree/main/src/sqlite",
		},
		{
			ID:          "filesystem",
			Name:        "Local Filesystem Sandbox",
			Description: "Read, write, and explore allowed directories on the host operating system with strict path isolation.",
			Category:    "data",
			Type:        "stdio",
			Command:     "npx",
			Args:            []string{"-y", "@modelcontextprotocol/server-filesystem", "."},
			Icon:        "folder",
			DocURL:      "https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem",
		},
		{
			ID:              "gdrive",
			Name:            "Google Drive Documents",
			Description:     "Search and extract text from Google Docs, Sheets, and cloud files stored in your organization.",
			Category:        "data",
			Type:            "stdio",
			Command:         "npx",
			Args:            []string{"-y", "@modelcontextprotocol/server-gdrive"},
			EnvRequirements: []string{"GOOGLE_DRIVE_CREDENTIALS"},
			Icon:            "file-text",
			DocURL:          "https://github.com/modelcontextprotocol/servers/tree/main/src/gdrive",
		},

		// --- 🔍 WEB & SEARCH ---
		{
			ID:              "brave-search",
			Name:            "Brave Search API",
			Description:     "Real-time web and local search results without user tracking or telemetry profiling.",
			Category:        "web",
			Type:            "stdio",
			Command:         "npx",
			Args:            []string{"-y", "@modelcontextprotocol/server-brave-search"},
			EnvRequirements: []string{"BRAVE_API_KEY"},
			Icon:            "search",
			DocURL:          "https://github.com/modelcontextprotocol/servers/tree/main/src/brave-search",
		},
		{
			ID:              "tavily",
			Name:            "Tavily AI Search",
			Description:     "Deep research search engine optimized specifically for LLMs and agentic reasoning pipelines.",
			Category:        "web",
			Type:            "stdio",
			Command:         "tavily-mcp",
			Args:            []string{},
			EnvRequirements: []string{"TAVILY_API_KEY"},
			Icon:            "globe",
			DocURL:          "https://tavily.com",
		},
		{
			ID:          "fetch",
			Name:        "Web Fetcher & HTML Reader",
			Description: "Fetch web pages and convert HTML content into clean markdown for token-efficient agent analysis.",
			Category:    "web",
			Type:        "stdio",
			Command:     "npx",
			Args:        []string{"-y", "@modelcontextprotocol/server-fetch"},
			Icon:        "download",
			DocURL:      "https://github.com/modelcontextprotocol/servers/tree/main/src/fetch",
		},
		{
			ID:          "puppeteer",
			Name:        "Puppeteer Browser Automation",
			Description: "Headless Chromium browser control for capturing screenshots, navigating SPAs, and filling forms.",
			Category:    "web",
			Type:        "stdio",
			Command:     "npx",
			Args:        []string{"-y", "@modelcontextprotocol/server-puppeteer"},
			Icon:        "chrome",
			DocURL:      "https://github.com/modelcontextprotocol/servers/tree/main/src/puppeteer",
		},

		// --- 💬 PRODUCTIVITY & WORKFLOW ---
		{
			ID:              "slack",
			Name:            "Slack Workspace",
			Description:     "List channels, read team threads, and broadcast automated summaries to specific channels.",
			Category:        "productivity",
			Type:            "stdio",
			Command:         "npx",
			Args:            []string{"-y", "@modelcontextprotocol/server-slack"},
			EnvRequirements: []string{"SLACK_BOT_TOKEN", "SLACK_TEAM_ID"},
			Icon:            "message-square",
			DocURL:          "https://github.com/modelcontextprotocol/servers/tree/main/src/slack",
		},
		{
			ID:              "discord",
			Name:            "Discord Community",
			Description:     "Monitor guild channels, send bot notifications, and interact with developer discord servers.",
			Category:        "productivity",
			Type:            "stdio",
			Command:         "mcp-discord",
			Args:            []string{},
			EnvRequirements: []string{"DISCORD_TOKEN"},
			Icon:            "message-circle",
			DocURL:          "https://github.com/modelcontextprotocol/servers",
		},
		{
			ID:              "linear",
			Name:            "Linear Issue Tracker",
			Description:     "Create, update, and search development issues, sprint cycles, and engineering roadmaps.",
			Category:        "productivity",
			Type:            "stdio",
			Command:         "mcp-linear",
			Args:            []string{},
			EnvRequirements: []string{"LINEAR_API_KEY"},
			Icon:            "check-square",
			DocURL:          "https://linear.app",
		},
		{
			ID:              "notion",
			Name:            "Notion Workspace",
			Description:     "Search knowledge base documents, update database entries, and read engineering wiki pages.",
			Category:        "productivity",
			Type:            "stdio",
			Command:         "npx",
			Args:            []string{"-y", "@modelcontextprotocol/server-notion"},
			EnvRequirements: []string{"NOTION_API_KEY"},
			Icon:            "book",
			DocURL:          "https://notion.so",
		},
		{
			ID:              "jira",
			Name:            "Atlassian Jira & Confluence",
			Description:     "Search sprint backlogs, log time entries, update ticket status, and query project issue trees.",
			Category:        "productivity",
			Type:            "stdio",
			Command:         "mcp-atlassian",
			Args:            []string{},
			EnvRequirements: []string{"JIRA_URL", "JIRA_API_TOKEN"},
			Icon:            "trello",
			DocURL:          "https://atlassian.com",
		},

		// --- 🧠 MEMORY & REASONING ---
		{
			ID:          "memory",
			Name:        "Knowledge Graph Memory",
			Description: "Persistent entity-based knowledge graph to remember user preferences, facts, and conversation context.",
			Category:    "memory",
			Type:        "stdio",
			Command:     "npx",
			Args:        []string{"-y", "@modelcontextprotocol/server-memory"},
			Icon:        "cpu",
			DocURL:      "https://github.com/modelcontextprotocol/servers/tree/main/src/memory",
		},
	}
}

// GetPresetsCatalog is an alias for GetPresets.
func GetPresetsCatalog() []PresetMetadata {
	return GetPresets()
}

