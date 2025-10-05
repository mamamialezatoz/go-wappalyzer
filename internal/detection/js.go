package detection

import (
	"github.com/mamamialezatoz/go-wappalyzer/internal/models"
	"github.com/mamamialezatoz/go-wappalyzer/internal/parser"
)

// MatchJS matches technologies based on JavaScript patterns
func MatchJS(jsPatterns map[string]map[string]*models.ParsedPattern, jsVars map[string]string, technologies map[string]struct{}) {
	// Check each technology's JS patterns
	for tech, techJsPatterns := range jsPatterns {
		for jsName, pattern := range techJsPatterns {
			if jsValue, ok := jsVars[jsName]; ok {
				if matched, _ := parser.EvaluatePattern(pattern, jsValue); matched {
					technologies[tech] = struct{}{}
					break
				}
			}
		}
	}
}
