package models

// DetectionResult represents the complete result of technology detection
type DetectionResult struct {
	// URL that was analyzed
	URL string
	// Title of the page
	Title string
	// Technologies detected
	Technologies map[string]TechnologyInfo
	// HTTP status code
	StatusCode int
	// Response time in milliseconds
	ResponseTime int64
}

// TechnologyInfo represents detailed information about a detected technology
type TechnologyInfo struct {
	// Name of the technology
	Name string
	// Description of the technology
	Description string
	// Website URL for the technology
	Website string
	// Version if detected
	Version string
	// Category IDs
	Categories []int
	// CPE identifier
	CPE string
	// Confidence of detection (0-100)
	Confidence int
	// How the technology was detected (e.g., "headers", "html", "cookies")
	DetectedBy []string
}

// Category represents a technology category
type Category struct {
	// ID of the category
	ID int
	// Name of the category
	Name string
}
