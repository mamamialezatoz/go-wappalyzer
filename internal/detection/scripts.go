package detection

import (
	"github.com/mamamialezatoz/go-wappalyzer/internal/models"
	"github.com/mamamialezatoz/go-wappalyzer/internal/parser"
)

// MatchScripts matches technologies based on script tags
func MatchScripts(scriptPatterns map[string][]*models.ParsedPattern, body []byte, technologies map[string]struct{}) {
	bodyStr := string(body)

	// Check each technology's script patterns
	for tech, patterns := range scriptPatterns {
		for _, pattern := range patterns {
			if matched, _ := parser.EvaluatePattern(pattern, bodyStr); matched {
				technologies[tech] = struct{}{}
				break
			}
		}
	}
}

// MatchScriptSrc matches technologies based on script src attributes
func MatchScriptSrc(scriptSrcPatterns map[string][]*models.ParsedPattern, scripts []models.ScriptPattern, technologies map[string]struct{}) {
	for tech, patterns := range scriptSrcPatterns {
		for _, pattern := range patterns {
			for _, script := range scripts {
				if script.Source != "" {
					if matched, _ := parser.EvaluatePattern(pattern, script.Source); matched {
						technologies[tech] = struct{}{}
						break
					}
				}
			}
		}
	}
}
