package parser

import (
	"reflect"
	"strings"

	"github.com/mamamialezatoz/go-wappalyzer/internal/models"
)

// CompileFingerprints compiles fingerprints from the original format to the optimized format
func CompileFingerprints(fingerprints *models.Fingerprints) (*models.CompiledFingerprints, error) {
	compiled := &models.CompiledFingerprints{
		Apps: make(map[string]*models.CompiledFingerprint),
	}

	// Process each app fingerprint
	for name, app := range fingerprints.Apps {
		compiledApp := &models.CompiledFingerprint{
			Cats:              app.Cats,
			Description:       app.Description,
			Website:           app.Website,
			CPE:               app.CPE,
			Icon:              app.Icon,
			Headers:           app.Headers,
			Cookies:           app.Cookies,
			HTML:              app.HTML,
			Script:            app.Script,
			ScriptSrc:         app.ScriptSrc,
			Meta:              app.Meta,
			JS:                app.JS,
			Implies:           app.Implies,
			HeaderPatterns:    make(map[string]*models.ParsedPattern),
			CookiePatterns:    make(map[string]*models.ParsedPattern),
			HTMLPatterns:      make([]*models.ParsedPattern, 0),
			ScriptPatterns:    make([]*models.ParsedPattern, 0),
			ScriptSrcPatterns: make([]*models.ParsedPattern, 0),
			MetaPatterns:      make(map[string][]*models.ParsedPattern),
			JSPatterns:        make(map[string]*models.ParsedPattern),
		}

		// Process implied technologies
		compiledApp.ImpliedTechs = processImpliesList(app.Implies)

		// Compile header patterns
		for header, pattern := range app.Headers {
			parsedPattern, err := ParsePattern(pattern)
			if err != nil {
				// Log error and continue with next pattern
				continue
			}
			compiledApp.HeaderPatterns[strings.ToLower(header)] = parsedPattern
		}

		// Compile cookie patterns
		for cookie, pattern := range app.Cookies {
			parsedPattern, err := ParsePattern(pattern)
			if err != nil {
				continue
			}
			compiledApp.CookiePatterns[strings.ToLower(cookie)] = parsedPattern
		}

		// Compile HTML patterns
		htmlPatterns := extractPatternList(app.HTML)
		for _, pattern := range htmlPatterns {
			parsedPattern, err := ParsePattern(pattern)
			if err != nil {
				continue
			}
			compiledApp.HTMLPatterns = append(compiledApp.HTMLPatterns, parsedPattern)
		}

		// Compile Script patterns
		scriptPatterns := extractPatternList(app.Script)
		for _, pattern := range scriptPatterns {
			parsedPattern, err := ParsePattern(pattern)
			if err != nil {
				continue
			}
			compiledApp.ScriptPatterns = append(compiledApp.ScriptPatterns, parsedPattern)
		}

		// Compile ScriptSrc patterns
		scriptSrcPatterns := extractPatternList(app.ScriptSrc)
		for _, pattern := range scriptSrcPatterns {
			parsedPattern, err := ParsePattern(pattern)
			if err != nil {
				continue
			}
			compiledApp.ScriptSrcPatterns = append(compiledApp.ScriptSrcPatterns, parsedPattern)
		}

		// Compile Meta patterns
		for metaName, patterns := range app.Meta {
			compiledPatterns := make([]*models.ParsedPattern, 0)

			// Extract meta patterns based on type
			metaPatterns := extractPatternList(patterns)
			for _, pattern := range metaPatterns {
				parsedPattern, err := ParsePattern(pattern)
				if err != nil {
					continue
				}
				compiledPatterns = append(compiledPatterns, parsedPattern)
			}

			if len(compiledPatterns) > 0 {
				compiledApp.MetaPatterns[strings.ToLower(metaName)] = compiledPatterns
			}
		}

		// Compile JS patterns
		for jsName, pattern := range app.JS {
			parsedPattern, err := ParsePattern(pattern)
			if err != nil {
				continue
			}
			compiledApp.JSPatterns[jsName] = parsedPattern
		}

		compiled.Apps[name] = compiledApp
	}

	return compiled, nil
}

// extractPatternList handles extraction of patterns from different data formats
func extractPatternList(data interface{}) []string {
	var patterns []string

	if data == nil {
		return patterns
	}

	v := reflect.ValueOf(data)
	switch v.Kind() {
	case reflect.String:
		patterns = append(patterns, v.String())
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			item := v.Index(i)
			if item.Kind() == reflect.String {
				patterns = append(patterns, item.String())
			} else if item.Kind() == reflect.Interface {
				if str, ok := item.Interface().(string); ok {
					patterns = append(patterns, str)
				}
			}
		}
	case reflect.Map:
		// For some formats, patterns might be in a map structure
		// This is a simplification; adjust based on actual data format
		for _, key := range v.MapKeys() {
			val := v.MapIndex(key)
			if val.Kind() == reflect.String {
				patterns = append(patterns, val.String())
			}
		}
	}

	return patterns
}

// processImpliesList extracts implied technologies list from different formats
func processImpliesList(implies interface{}) []string {
	var impliedTechs []string

	if implies == nil {
		return impliedTechs
	}

	v := reflect.ValueOf(implies)
	switch v.Kind() {
	case reflect.String:
		impliedTechs = append(impliedTechs, v.String())
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			item := v.Index(i)
			if item.Kind() == reflect.String {
				impliedTechs = append(impliedTechs, item.String())
			} else if item.Kind() == reflect.Interface {
				if str, ok := item.Interface().(string); ok {
					impliedTechs = append(impliedTechs, str)
				}
			}
		}
	}

	return impliedTechs
}
