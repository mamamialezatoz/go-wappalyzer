package parser

import (
	"regexp"
	"strings"

	"github.com/mamamialezatoz/go-wappalyzer/internal/models"
)

var (
	// Regex for extracting meta tags from HTML
	metaTagRegex = regexp.MustCompile(`(?i)<meta[^>]+name=["']([^"']+)["'][^>]+content=["']([^"']+)["']|<meta[^>]+content=["']([^"']+)["'][^>]+name=["']([^"']+)["']`)

	// Regex for extracting script tags from HTML
	scriptRegex = regexp.MustCompile(`(?i)<script[^>]*src=["']([^"']+)["'][^>]*>|<script[^>]*>([\s\S]*?)</script>`)

	// Regex for extracting title from HTML
	titleRegex = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)

	// Regex for extracting JavaScript variables from script tags
	jsVarRegex = regexp.MustCompile(`(?i)var\s+([a-zA-Z0-9_$]+)\s*=\s*["']([^"']+)["']`)
)

// ExtractMetaTags extracts meta tags from HTML content
func ExtractMetaTags(body []byte) map[string]string {
	matches := metaTagRegex.FindAllSubmatch(body, -1)
	results := make(map[string]string)

	for _, match := range matches {
		var name, content string

		if len(match[1]) > 0 && len(match[2]) > 0 {
			name = string(match[1])
			content = string(match[2])
		} else if len(match[3]) > 0 && len(match[4]) > 0 {
			name = string(match[4])
			content = string(match[3])
		} else {
			continue
		}

		results[strings.ToLower(name)] = content
	}

	return results
}

// ExtractScripts extracts script tags and their content from HTML
func ExtractScripts(body []byte) []models.ScriptPattern {
	matches := scriptRegex.FindAllSubmatch(body, -1)
	results := make([]models.ScriptPattern, 0, len(matches))

	for _, match := range matches {
		script := models.ScriptPattern{}

		if len(match[1]) > 0 {
			script.Source = string(match[1])
		}

		if len(match[2]) > 0 {
			script.Content = string(match[2])
		}

		if script.Source != "" || script.Content != "" {
			results = append(results, script)
		}
	}

	return results
}

// ExtractTitle extracts the title from HTML content
func ExtractTitle(body []byte) string {
	match := titleRegex.FindSubmatch(body)
	if len(match) > 1 {
		return string(match[1])
	}
	return ""
}

// ExtractJS extracts JavaScript variables from HTML
func ExtractJS(body []byte) map[string]string {
	// Extract script contents first
	scripts := ExtractScripts(body)
	results := make(map[string]string)

	for _, script := range scripts {
		if script.Content == "" {
			continue
		}

		// Find variable declarations
		matches := jsVarRegex.FindAllSubmatch([]byte(script.Content), -1)
		for _, match := range matches {
			if len(match) >= 3 {
				varName := string(match[1])
				varValue := string(match[2])
				results[varName] = varValue
			}
		}
	}

	return results
}
