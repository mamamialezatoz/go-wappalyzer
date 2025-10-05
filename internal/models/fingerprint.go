package models

import "fmt"

// Fingerprints contains a map of fingerprints for tech detection
type Fingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]*Fingerprint `json:"apps"`
}

// Fingerprint is a single piece of information about a tech
type Fingerprint struct {
	Cats        []int                  `json:"cats"`
	Description string                 `json:"description"`
	Icon        string                 `json:"icon"`
	Website     string                 `json:"website"`
	CPE         string                 `json:"cpe"`
	Cookies     map[string]string      `json:"cookies"`
	JS          map[string]string      `json:"js"`
	Headers     map[string]string      `json:"headers"`
	HTML        interface{}            `json:"html"`
	Script      interface{}            `json:"scripts"`
	ScriptSrc   interface{}            `json:"scriptSrc"`
	Meta        map[string]interface{} `json:"meta"`
	Implies     interface{}            `json:"implies"`
	Name        string                 `json:"name"`
}

// Technology represents a single technology from the new array-based format
type Technology struct {
	Name        string                 `json:"name"`
	Cats        []int                  `json:"cats"`
	Description string                 `json:"description"`
	Website     string                 `json:"website"`
	CPE         string                 `json:"cpe"`
	Icon        string                 `json:"icon"`
	Cookies     map[string]string      `json:"cookies"`
	JS          map[string]interface{} `json:"js"`
	Headers     map[string]string      `json:"headers"`
	HTML        interface{}            `json:"html"`
	Scripts     interface{}            `json:"scripts"`
	ScriptSrc   interface{}            `json:"scriptSrc"`
	Meta        map[string]interface{} `json:"meta"`
	Implies     interface{}            `json:"implies"`
}

// Technologies represents the array of technologies from the new format
type Technologies []Technology

// ConvertToFingerprints converts an array of technologies to the map structure used internally
func ConvertToFingerprints(techs Technologies) *Fingerprints {
	fingerprints := &Fingerprints{
		Apps: make(map[string]*Fingerprint),
	}

	for _, tech := range techs {
		fingerprints.Apps[tech.Name] = &Fingerprint{
			Name:        tech.Name,
			Cats:        tech.Cats,
			Description: tech.Description,
			Icon:        tech.Icon,
			Website:     tech.Website,
			CPE:         tech.CPE,
			Cookies:     tech.Cookies,
			JS:          convertJSMap(tech.JS),
			Headers:     tech.Headers,
			HTML:        tech.HTML,
			Script:      tech.Scripts,
			ScriptSrc:   tech.ScriptSrc,
			Meta:        tech.Meta,
			Implies:     tech.Implies,
		}
	}

	return fingerprints
}

// convertJSMap converts the JS map from the new structure to the old one
// The new format uses map[string]interface{} while the old one uses map[string]string
func convertJSMap(jsMap map[string]interface{}) map[string]string {
	if jsMap == nil {
		return nil
	}

	result := make(map[string]string)
	for key, value := range jsMap {
		switch v := value.(type) {
		case string:
			result[key] = v
		case bool:
			if v {
				result[key] = "true"
			} else {
				result[key] = "false"
			}
		case float64, int, int64:
			result[key] = fmt.Sprintf("%v", v)
		default:
			// For other types, just store an empty string
			result[key] = ""
		}
	}

	return result
}

// CompiledFingerprints contains a map of fingerprints for tech detection
type CompiledFingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]*CompiledFingerprint
}

// CompiledFingerprint contains the compiled fingerprints from the tech json
type CompiledFingerprint struct {
	// Raw values from the fingerprint
	Cats        []int
	Description string
	Website     string
	CPE         string
	Icon        string
	Headers     map[string]string
	Cookies     map[string]string
	HTML        interface{}
	Script      interface{}
	ScriptSrc   interface{}
	Meta        map[string]interface{}
	JS          map[string]string
	Implies     interface{}

	// Compiled patterns
	HeaderPatterns    map[string]*ParsedPattern
	CookiePatterns    map[string]*ParsedPattern
	HTMLPatterns      []*ParsedPattern
	ScriptPatterns    []*ParsedPattern
	ScriptSrcPatterns []*ParsedPattern
	MetaPatterns      map[string][]*ParsedPattern
	JSPatterns        map[string]*ParsedPattern

	// Implied technologies
	ImpliedTechs []string
}

// AppInfo contains basic information about an App
type AppInfo struct {
	Description string
	Website     string
}

// CatsInfo contains category information about an App
type CatsInfo struct {
	Cats []int
}

// LogoAndInfo contains complete information about an App including its logo
type LogoAndInfo struct {
	Description   string
	Website       string
	CPE           string
	Logo          string
	DominantColor string
	Cats          []int
}
