package detection

import (
	"strings"

	"github.com/mamamialezatoz/go-wappalyzer/internal/models"
	"github.com/mamamialezatoz/go-wappalyzer/internal/parser"
)

// MatchHeaders matches technologies based on HTTP headers
func MatchHeaders(headerPatterns map[string]map[string]*models.ParsedPattern, headers map[string][]string, technologies map[string]struct{}) {
	// Convert headers to lowercase for case-insensitive matching
	normalizedHeaders := make(map[string][]string)
	for header, values := range headers {
		normalizedHeaders[strings.ToLower(header)] = values
	}

	// Check each technology's header patterns
	for tech, techHeaderPatterns := range headerPatterns {
		for headerName, pattern := range techHeaderPatterns {
			headerName = strings.ToLower(headerName)

			if headerValues, ok := normalizedHeaders[headerName]; ok {
				for _, headerValue := range headerValues {
					if matched, _ := parser.EvaluatePattern(pattern, headerValue); matched {
						technologies[tech] = struct{}{}
						break
					}
				}
			}
		}
	}
}

// ExtractCookiesFromHeaders extracts cookies from HTTP headers
func ExtractCookiesFromHeaders(headers map[string][]string) map[string]string {
	cookies := make(map[string]string)

	// Look for the Cookie header
	if cookieHeaders, ok := headers["Cookie"]; ok {
		for _, cookieHeader := range cookieHeaders {
			// Split the cookie header by semicolon
			cookiePairs := strings.Split(cookieHeader, ";")

			for _, cookiePair := range cookiePairs {
				cookiePair = strings.TrimSpace(cookiePair)
				if cookiePair == "" {
					continue
				}

				// Split the cookie pair by =
				parts := strings.SplitN(cookiePair, "=", 2)
				if len(parts) < 2 {
					continue
				}

				name := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				// Store in the map
				cookies[strings.ToLower(name)] = value
			}
		}
	}

	// Also look for the Set-Cookie header
	if setCookieHeaders, ok := headers["Set-Cookie"]; ok {
		for _, setCookieHeader := range setCookieHeaders {
			// Extract the cookie name and value
			cookieParts := strings.SplitN(setCookieHeader, ";", 2)
			if len(cookieParts) == 0 {
				continue
			}

			nameValuePair := strings.SplitN(cookieParts[0], "=", 2)
			if len(nameValuePair) < 2 {
				continue
			}

			name := strings.TrimSpace(nameValuePair[0])
			value := strings.TrimSpace(nameValuePair[1])

			// Store in the map
			cookies[strings.ToLower(name)] = value
		}
	}

	return cookies
}
