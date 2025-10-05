package models

// ParsedPattern represents a parsed regex pattern with additional information
type ParsedPattern struct {
	// Original pattern as a string
	Pattern string
	// Whether the pattern is a simple string match
	IsLiteral bool
	// Whether the pattern is case sensitive
	IsCaseSensitive bool
	// Version information if available
	Version string
	// Confidence score (0-100)
	Confidence int
	// Skip regex compilation (for optimization)
	SkipRegex bool
}

// MetaTag represents a HTML meta tag with name and content
type MetaTag struct {
	Name    string
	Content string
}

// JSPattern represents a JavaScript pattern with name and value
type JSPattern struct {
	Name  string
	Value string
}

// CookiePattern represents a cookie with name and value
type CookiePattern struct {
	Name  string
	Value string
}

// HeaderPattern represents an HTTP header with name and value
type HeaderPattern struct {
	Name  string
	Value string
}

// ScriptPattern represents a script tag with content or source
type ScriptPattern struct {
	Source  string
	Content string
}
