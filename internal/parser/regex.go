package parser

import (
	"fmt"
	"regexp"
	"strings"
)

// CompileRegex compiles a regular expression string into a regexp.Regexp
// It caches the compiled regexes for better performance
func CompileRegex(pattern string) (*regexp.Regexp, error) {
	// Check if we have it in cache
	if compiled, ok := regexCache[pattern]; ok {
		return compiled, nil
	}

	// Normalize the pattern
	normalizedPattern := normalizePattern(pattern)

	// Compile the regex
	compiled, err := regexp.Compile(normalizedPattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex '%s': %v", pattern, err)
	}

	// Cache it
	regexCache[pattern] = compiled

	return compiled, nil
}

// normalizePattern normalizes a regular expression pattern
func normalizePattern(pattern string) string {
	// Handle special case where pattern is surrounded by "/" (common in JavaScript regex)
	if len(pattern) > 2 && pattern[0] == '/' && pattern[len(pattern)-1] == '/' {
		pattern = pattern[1 : len(pattern)-1]
	}

	// Handle the case where we need to make the pattern case insensitive
	if !strings.HasPrefix(pattern, "(?i)") && !strings.Contains(pattern, "(?-i)") {
		pattern = "(?i)" + pattern
	}

	return pattern
}
