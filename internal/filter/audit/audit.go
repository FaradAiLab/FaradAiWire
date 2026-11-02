package audit

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Issue represents a security vulnerability, risk, or opaque payload found in a skill file.
type Issue struct {
	FilePath string         `json:"file_path"`
	LineNum  int            `json:"line_num"`
	Code     string         `json:"code"`
	Severity string         `json:"severity"` // "CRITICAL", "HIGH", "WARNING", "INFO"
	Category ThreatCategory `json:"category"`
	Reason   string         `json:"reason"`
	RuleID   string         `json:"rule_id,omitempty"`
}

// AuditReport aggregates all findings, file counts, and category statistics for an audit run.
type AuditReport struct {
	RootPath          string                 `json:"root_path"`
	ScannedFilesCount int                    `json:"scanned_files_count"`
	FilesByLanguage   map[string]int         `json:"files_by_language"`
	Issues            []Issue                `json:"issues"`
	PassedCategories  map[ThreatCategory]bool `json:"passed_categories"`
	FailedCategories  map[ThreatCategory]int  `json:"failed_categories"`
}

// Target extensions mapped to language display names
var targetExtensions = map[string]string{
	".go":   "Go",
	".py":   "Python",
	".sh":   "Bash",
	".bash": "Bash",
	".zsh":  "Zsh",
	".js":   "JavaScript",
	".ts":   "TypeScript",
	".jsx":  "JavaScript",
	".tsx":  "TypeScript",
	".md":   "Markdown",
	".json": "JSON",
	".yaml": "YAML",
	".yml":  "YAML",
}

var opaqueBinaryExtensions = map[string]bool{
	".exe":   true,
	".dll":   true,
	".so":    true,
	".dylib": true,
	".bin":   true,
	".elf":   true,
	".o":     true,
	".a":     true,
	".wasm":  true,
}

// Directories skipped during recursive walk
var ignoredDirectories = map[string]bool{
	".git":         true,
	".svn":         true,
	".hg":          true,
	"node_modules": true,
	"vendor":       true,
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
	".idea":        true,
	".vscode":      true,
}

// AuditDirectory recursively scans files in the directory for security risks,
// backdoors, and opaque binaries using the in-memory canonical policy catalog.
func AuditDirectory(root string) (*AuditReport, error) {
	rules, err := LoadAuditRuleCatalog()
	if err != nil {
		return nil, fmt.Errorf("load audit catalog: %w", err)
	}

	report := &AuditReport{
		RootPath:         root,
		FilesByLanguage:  make(map[string]int),
		Issues:           make([]Issue, 0),
		PassedCategories: make(map[ThreatCategory]bool),
		FailedCategories: make(map[ThreatCategory]int),
	}

	// Canonical categories to track for pass/fail status
	canonicalCategories := []ThreatCategory{
		CategoryShellExecution,
		CategoryCredentialHarvesting,
		CategoryDestructiveCommands,
		CategoryPrivilegeEscalation,
		CategoryDangerousEval,
		CategoryNetworkBackdoor,
		CategoryOpaqueBinary,
	}
	for _, c := range canonicalCategories {
		report.PassedCategories[c] = true
	}

	realRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve audit root: %w", err)
	}

	err = filepath.Walk(realRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if info.IsDir() {
			if ignoredDirectories[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		// Security: Prevent symlink escape outside the target root directory
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil || !strings.HasPrefix(resolved, realRoot) {
				// Skip symlinks pointing outside target root
				return nil
			}
		}

		// 1. Check for opaque compiled binaries
		if isBinary, binaryType := checkOpaqueBinary(path, info); isBinary {
			relPath, _ := filepath.Rel(realRoot, path)
			if relPath == "" {
				relPath = path
			}
			report.Issues = append(report.Issues, Issue{
				FilePath: relPath,
				LineNum:  1,
				Code:     fmt.Sprintf("[OPAQUE BINARY: %s]", binaryType),
				Severity: "CRITICAL",
				Category: CategoryOpaqueBinary,
				Reason:   "Opaque compiled binary payload detected; agent skills must be transparent human-readable source code",
				RuleID:   "audit:opaque-binary",
			})
			report.FailedCategories[CategoryOpaqueBinary]++
			report.PassedCategories[CategoryOpaqueBinary] = false
			return nil
		}

		// 2. Check if file matches inspectable text/code extensions
		ext := strings.ToLower(filepath.Ext(path))
		lang, isTarget := targetExtensions[ext]
		if !isTarget {
			return nil
		}

		report.ScannedFilesCount++
		report.FilesByLanguage[lang]++

		relPath, _ := filepath.Rel(realRoot, path)
		if relPath == "" {
			relPath = path
		}

		fileIssues, err := scanFile(path, relPath, rules)
		if err != nil {
			// Log error and continue to scan other files
			return nil
		}

		for _, issue := range fileIssues {
			report.Issues = append(report.Issues, issue)
			report.FailedCategories[issue.Category]++
			report.PassedCategories[issue.Category] = false
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walk directory %s: %w", root, err)
	}

	return report, nil
}

// AuditDirectoryLegacy provides backwards-compatibility returning a slice of issues.
func AuditDirectoryLegacy(root string) ([]Issue, error) {
	report, err := AuditDirectory(root)
	if err != nil {
		return nil, err
	}
	return report.Issues, nil
}

func scanFile(fullPath, displayPath string, rules []AuditRule) ([]Issue, error) {
	file, err := os.Open(fullPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var issues []Issue
	scanner := bufio.NewScanner(file)
	// Buffer up to 64KB per line
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 64*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Ignore Markdown code fence delimiters (e.g. ```bash, ```sh, ```python, ```)
		if strings.HasPrefix(trimmed, "```") && len(trimmed) <= 32 && !strings.ContainsAny(trimmed, ";&|()") {
			continue
		}

		for _, r := range rules {
			if r.Pattern.MatchString(line) {
				issues = append(issues, Issue{
					FilePath: displayPath,
					LineNum:  lineNum,
					Code:     trimmed,
					Severity: r.Severity,
					Category: r.Category,
					Reason:   r.Reason,
					RuleID:   r.ID,
				})
			}
		}
	}

	return issues, scanner.Err()
}

// checkOpaqueBinary inspects file extension and first 512 magic bytes
// to detect compiled executables, shared libraries, or high null-byte payloads.
func checkOpaqueBinary(path string, info os.FileInfo) (bool, string) {
	ext := strings.ToLower(filepath.Ext(path))
	if opaqueBinaryExtensions[ext] {
		return true, fmt.Sprintf("Extension %s", ext)
	}

	// If file is smaller than 4 bytes, cannot be executable binary format
	if info.Size() < 4 {
		return false, ""
	}

	f, err := os.Open(path)
	if err != nil {
		return false, ""
	}
	defer f.Close()

	header := make([]byte, 512)
	n, err := f.Read(header)
	if err != nil && err != io.EOF {
		return false, ""
	}
	header = header[:n]

	// 1. ELF Binary (Linux / Unix executable)
	if len(header) >= 4 && bytes.Equal(header[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return true, "ELF Executable"
	}

	// 2. Mach-O Binary (macOS 32/64-bit & universal binary)
	if len(header) >= 4 {
		if bytes.Equal(header[:4], []byte{0xfe, 0xed, 0xfa, 0xce}) ||
			bytes.Equal(header[:4], []byte{0xfe, 0xed, 0xfa, 0xcf}) ||
			bytes.Equal(header[:4], []byte{0xce, 0xfa, 0xed, 0xfe}) ||
			bytes.Equal(header[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}) ||
			bytes.Equal(header[:4], []byte{0xca, 0xfe, 0xba, 0xbe}) { // Universal / Java Class
			return true, "Mach-O / JVM Binary"
		}
	}

	// 3. Windows PE / Portable Executable (starts with 'MZ')
	if len(header) >= 2 && header[0] == 'M' && header[1] == 'Z' && ext != ".txt" && ext != ".md" {
		return true, "Windows PE Executable"
	}

	// 4. WebAssembly (.wasm magic: \x00asm)
	if len(header) >= 4 && bytes.Equal(header[:4], []byte{0x00, 0x61, 0x73, 0x6d}) {
		return true, "WebAssembly Module"
	}

	// 5. Heuristic check: High null-byte concentration in small header indicates non-text binary
	if n >= 64 {
		nullBytes := 0
		for _, b := range header {
			if b == 0x00 {
				nullBytes++
			}
		}
		// If more than 30% of first bytes are null bytes, classify as opaque binary
		if float64(nullBytes)/float64(n) > 0.30 {
			return true, "Opaque Binary Stream"
		}
	}

	return false, ""
}

// FormatLanguageBreakdown produces a comma-separated string of scanned languages.
func (r *AuditReport) FormatLanguageBreakdown() string {
	if len(r.FilesByLanguage) == 0 {
		return "0 files"
	}
	langs := make([]string, 0, len(r.FilesByLanguage))
	for l := range r.FilesByLanguage {
		langs = append(langs, l)
	}
	sort.Strings(langs)
	return strings.Join(langs, ", ")
}
