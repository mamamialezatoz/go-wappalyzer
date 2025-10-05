package wappalyzer

// Config contains configuration options for the wappalyzer client
type Config struct {
	// JSON contains the fingerprints data, if provided directly
	JSON []byte
	// DisableJSDetection disables JavaScript pattern detection
	DisableJSDetection bool
	// DisableHTMLDetection disables HTML pattern detection
	DisableHTMLDetection bool
	// DisableCookieDetection disables cookie detection
	DisableCookieDetection bool
	// DisableHeaderDetection disables header detection
	DisableHeaderDetection bool
	// DisableMetaDetection disables meta tag detection
	DisableMetaDetection bool
	// DisableScriptDetection disables script tag detection
	DisableScriptDetection bool
	// MaxBodySize limits the maximum body size to scan
	MaxBodySize int
}

// Option is a function that configures the wappalyzer client
type Option func(*Config)

// WithCustomFingerprints sets custom fingerprints data
func WithCustomFingerprints(fingerprints []byte) Option {
	return func(c *Config) {
		c.JSON = fingerprints
	}
}

// WithMaxBodySize sets the maximum body size to scan
func WithMaxBodySize(size int) Option {
	return func(c *Config) {
		c.MaxBodySize = size
	}
}

// WithoutJSDetection disables JavaScript pattern detection
func WithoutJSDetection() Option {
	return func(c *Config) {
		c.DisableJSDetection = true
	}
}

// WithoutHTMLDetection disables HTML pattern detection
func WithoutHTMLDetection() Option {
	return func(c *Config) {
		c.DisableHTMLDetection = true
	}
}

// WithoutCookieDetection disables cookie detection
func WithoutCookieDetection() Option {
	return func(c *Config) {
		c.DisableCookieDetection = true
	}
}

// WithoutHeaderDetection disables header detection
func WithoutHeaderDetection() Option {
	return func(c *Config) {
		c.DisableHeaderDetection = true
	}
}

// WithoutMetaDetection disables meta tag detection
func WithoutMetaDetection() Option {
	return func(c *Config) {
		c.DisableMetaDetection = true
	}
}

// WithoutScriptDetection disables script tag detection
func WithoutScriptDetection() Option {
	return func(c *Config) {
		c.DisableScriptDetection = true
	}
}

// WithAllDetections enables all detection methods
func WithAllDetections() Option {
	return func(c *Config) {
		c.DisableJSDetection = false
		c.DisableHTMLDetection = false
		c.DisableCookieDetection = false
		c.DisableHeaderDetection = false
		c.DisableMetaDetection = false
		c.DisableScriptDetection = false
	}
}
