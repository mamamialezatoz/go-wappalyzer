package parser

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/mamamialezatoz/go-wappalyzer/internal/models"
)

var (
	// Cache of compiled regular expressions
	regexCache = make(map[string]*regexp.Regexp)

	// Common version detection patterns
	versionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\\;version:(.+)`),
		regexp.MustCompile(`[^\d](\d+(?:\.\d+)+)`),
		regexp.MustCompile(`\bv?(\d+(?:\.\d+)+)`),
		regexp.MustCompile(`version[:/\s]*([\d.]+)`),
	}
)

// ParsePattern parses a pattern string into a structured model
// This is crucial for pattern matching in fingerprinting
func ParsePattern(pattern string) (*models.ParsedPattern, error) {
	parsedPattern := &models.ParsedPattern{
		Pattern:         pattern,
		IsLiteral:       !isRegexPattern(pattern),
		IsCaseSensitive: isCaseSensitive(pattern),
		Confidence:      100, // Default confidence
	}

	// Check for version extraction
	version, confidence := extractVersionInfo(pattern)
	if version != "" {
		parsedPattern.Version = version
		parsedPattern.Confidence = confidence
	}

	// Clean the pattern if it contains version info
	cleanedPattern := cleanPatternString(pattern)

	// If it's a regex pattern, try to compile it
	if !parsedPattern.IsLiteral {
		if _, err := CompileRegex(cleanedPattern); err != nil {
			return nil, fmt.Errorf("invalid regex pattern: %v", err)
		}
		parsedPattern.Pattern = cleanedPattern
	}

	return parsedPattern, nil
}

// EvaluatePattern checks if a target string matches the pattern and extracts version info
func EvaluatePattern(pattern *models.ParsedPattern, target string) (bool, string) {
	// For literal patterns, perform simple contains check
	if pattern.IsLiteral {
		if pattern.IsCaseSensitive {
			return strings.Contains(target, pattern.Pattern), pattern.Version
		}
		return strings.Contains(
			strings.ToLower(target),
			strings.ToLower(pattern.Pattern),
		), pattern.Version
	}

	// For regex patterns, use the compiled regex
	regex, err := CompileRegex(pattern.Pattern)
	if err != nil {
		return false, ""
	}

	// If the pattern matches, extract version if not already known
	if regex.MatchString(target) {
		version := pattern.Version

		// If no version in pattern, try to extract from target
		if version == "" {
			for _, vp := range versionPatterns {
				match := vp.FindStringSubmatch(target)
				if len(match) > 1 {
					version = match[1]
					break
				}
			}
		}

		return true, version
	}

	return false, ""
}

// isRegexPattern checks if the pattern is a regular expression
func isRegexPattern(pattern string) bool {
	// Check for common regex characters
	specialChars := []string{"\\", "^", "$", ".", "|", "?", "*", "+", "(", "[", "{"}
	for _, char := range specialChars {
		if strings.Contains(pattern, char) {
			return true
		}
	}

	// Check if pattern is surrounded by "/"
	if len(pattern) > 2 && pattern[0] == '/' && pattern[len(pattern)-1] == '/' {
		return true
	}

	return false
}

// isCaseSensitive checks if the pattern is case sensitive
func isCaseSensitive(pattern string) bool {
	// If pattern explicitly has case sensitivity modifiers
	return strings.Contains(pattern, "(?-i)") && !strings.Contains(pattern, "(?i)")
}

// extractVersionInfo extracts version information and confidence from a pattern
func extractVersionInfo(pattern string) (string, int) {
	// First try to extract version from Wappalyzer specific format
	parts := strings.Split(pattern, "\\;")
	if len(parts) > 1 {
		for _, part := range parts[1:] {
			if strings.HasPrefix(part, "version:") {
				return strings.TrimPrefix(part, "version:"), 80
			}
			if strings.HasPrefix(part, "confidence:") {
				confidence := 100 // Default
				fmt.Sscanf(strings.TrimPrefix(part, "confidence:"), "%d", &confidence)
				return "", confidence
			}
		}
	}

	// Try common version patterns
	for _, vp := range versionPatterns {
		match := vp.FindStringSubmatch(pattern)
		if len(match) > 1 {
			return match[1], 70 // Lower confidence for generic patterns
		}
	}

	return "", 100 // No version, default confidence
}

// cleanPatternString removes Wappalyzer-specific directives from patterns
func cleanPatternString(pattern string) string {
	// Remove version and other directives
	index := strings.Index(pattern, "\\;")
	if index > 0 {
		pattern = pattern[:index]
	}

	// Handle special case where pattern is surrounded by "/" (common in JavaScript regex)
	if len(pattern) > 2 && pattern[0] == '/' && pattern[len(pattern)-1] == '/' {
		pattern = pattern[1 : len(pattern)-1]
	}

	return pattern
}
