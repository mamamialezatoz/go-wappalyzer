package detection

import (
	"strings"

	"github.com/mamamialezatoz/go-wappalyzer/internal/models"
	"github.com/mamamialezatoz/go-wappalyzer/internal/parser"
)

// MatchCookies matches technologies based on cookies
func MatchCookies(cookiePatterns map[string]map[string]*models.ParsedPattern, cookies map[string]string, technologies map[string]struct{}) {
	// Normalize cookie names to lowercase
	normalizedCookies := make(map[string]string)
	for name, value := range cookies {
		normalizedCookies[strings.ToLower(name)] = value
	}

	// Check each technology's cookie patterns
	for tech, techCookiePatterns := range cookiePatterns {
		for cookieName, pattern := range techCookiePatterns {
			cookieName = strings.ToLower(cookieName)

			if cookieValue, ok := normalizedCookies[cookieName]; ok {
				if matched, _ := parser.EvaluatePattern(pattern, cookieValue); matched {
					technologies[tech] = struct{}{}
					break
				}
			}
		}
	}
}
