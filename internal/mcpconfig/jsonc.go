package mcpconfig

import (
	"bytes"
	"errors"
)

var (
	// ErrUnterminatedString indicates a syntax error where a string literal was not closed.
	ErrUnterminatedString = errors.New("jsonc: unterminated string literal")
	// ErrUnterminatedBlockComment indicates a multi-line comment was not closed.
	ErrUnterminatedBlockComment = errors.New("jsonc: unterminated block comment")
)

// StripCommentsAndTrailingCommas processes JSON with Comments (JSONC) into standard RFC-compliant JSON.
// It removes single-line comments (//), multi-line comments (/* ... */), and trailing commas before
// closing braces or brackets, while preserving newlines and string literals.
// Optimized for zero-heap growth in the common path by preallocating output buffers.
func StripCommentsAndTrailingCommas(src []byte) ([]byte, error) {
	n := len(src)
	if n == 0 {
		return src, nil
	}

	// Phase 1: Strip single-line and multi-line comments.
	// Preallocate output slice with exact input capacity to avoid reallocations.
	buf := make([]byte, 0, n)
	i := 0
	inString := false

	for i < n {
		b := src[i]

		if inString {
			buf = append(buf, b)
			if b == '\\' && i+1 < n {
				// Append escaped byte directly to avoid treating escaped quote as closing string
				i++
				buf = append(buf, src[i])
			} else if b == '"' {
				inString = false
			}
			i++
			continue
		}

		// Check for string start
		if b == '"' {
			inString = true
			buf = append(buf, b)
			i++
			continue
		}

		// Check for comment start
		if b == '/' && i+1 < n {
			next := src[i+1]
			if next == '/' {
				// Single-line comment: skip until newline or EOF
				i += 2
				for i < n && src[i] != '\n' && src[i] != '\r' {
					i++
				}
				// Preserve newline character so line counting stays aligned
				if i < n {
					buf = append(buf, src[i])
					i++
				}
				continue
			} else if next == '*' {
				// Block comment: skip until */
				i += 2
				closed := false
				for i+1 < n {
					if src[i] == '\n' {
						buf = append(buf, '\n') // retain newline for line numbering
					}
					if src[i] == '*' && src[i+1] == '/' {
						i += 2
						closed = true
						break
					}
					i++
				}
				if !closed {
					return nil, ErrUnterminatedBlockComment
				}
				continue
			}
		}

		buf = append(buf, b)
		i++
	}

	if inString {
		return nil, ErrUnterminatedString
	}

	// Phase 2: Strip trailing commas before closing braces '}' and closing brackets ']'.
	cleaned := stripTrailingCommas(buf)
	return cleaned, nil
}

// stripTrailingCommas removes commas immediately preceding closing braces or brackets (ignoring whitespace).
func stripTrailingCommas(src []byte) []byte {
	n := len(src)
	if n == 0 {
		return src
	}

	out := make([]byte, 0, n)
	inString := false
	var lastCommaIdx int = -1

	for i := 0; i < n; i++ {
		b := src[i]

		if inString {
			out = append(out, b)
			if b == '\\' && i+1 < n {
				i++
				out = append(out, src[i])
			} else if b == '"' {
				inString = false
			}
			continue
		}

		if b == '"' {
			inString = true
			lastCommaIdx = -1
			out = append(out, b)
			continue
		}

		if b == ',' {
			lastCommaIdx = len(out)
			out = append(out, b)
			continue
		}

		// Closing delimiter checks
		if b == '}' || b == ']' {
			if lastCommaIdx != -1 {
				// Verify everything between lastCommaIdx and current position is whitespace
				onlyWhitespace := true
				for k := lastCommaIdx + 1; k < len(out); k++ {
					if !isWhitespace(out[k]) {
						onlyWhitespace = false
						break
					}
				}
				if onlyWhitespace {
					// Remove the comma by shifting
					out = append(out[:lastCommaIdx], out[lastCommaIdx+1:]...)
				}
				lastCommaIdx = -1
			}
			out = append(out, b)
			continue
		}

		if !isWhitespace(b) {
			lastCommaIdx = -1
		}

		out = append(out, b)
	}

	return bytes.TrimSpace(out)
}

func isWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}
