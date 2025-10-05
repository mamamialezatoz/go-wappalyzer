package detection

import (
	"strings"

	"github.com/mamamialezatoz/go-wappalyzer/internal/models"
	"github.com/mamamialezatoz/go-wappalyzer/internal/parser"
)

// MatchMetaTags matches technologies based on meta tags
func MatchMetaTags(metaPatterns map[string]map[string][]*models.ParsedPattern, metaTags map[string]string, technologies map[string]struct{}) {
	// Normalize meta names to lowercase
	normalizedMeta := make(map[string]string)
	for name, content := range metaTags {
		normalizedMeta[strings.ToLower(name)] = content
	}

	// Check each technology's meta patterns
	for tech, techMetaPatterns := range metaPatterns {
		for metaName, patterns := range techMetaPatterns {
			metaName = strings.ToLower(metaName)

			if metaContent, ok := normalizedMeta[metaName]; ok {
				for _, pattern := range patterns {
					if matched, _ := parser.EvaluatePattern(pattern, metaContent); matched {
						technologies[tech] = struct{}{}
						break
					}
				}
			}
		}
	}
}
