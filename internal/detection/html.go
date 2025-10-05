package detection

import (
	"github.com/mamamialezatoz/go-wappalyzer/internal/models"
	"github.com/mamamialezatoz/go-wappalyzer/internal/parser"
)

// MatchHTML matches technologies based on HTML content
func MatchHTML(htmlPatterns map[string][]*models.ParsedPattern, body []byte, technologies map[string]struct{}) {
	bodyStr := string(body)

	// Check each technology's HTML patterns
	for tech, patterns := range htmlPatterns {
		for _, pattern := range patterns {
			if matched, _ := parser.EvaluatePattern(pattern, bodyStr); matched {
				technologies[tech] = struct{}{}
				break
			}
		}
	}
}
