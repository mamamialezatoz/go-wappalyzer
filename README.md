# go-wappalyzer

A high-performance Go implementation of the Wappalyzer technology detection library, with automatic fingerprint downloading capabilities and improved modularity.

## Features

- Fast and accurate technology detection for websites
- **Automatic fingerprint downloads** from [ZeroCostAutomation/wappalyzer-fingerprints](https://github.com/ZeroCostAutomation/wappalyzer-fingerprints)
- Local caching of fingerprint data with configurable TTL
- Clean, modular code structure for improved maintainability
- Low memory footprint and optimized performance
- Support for Go 1.18 and later
- Comprehensive detection methods (headers, cookies, HTML, scripts, meta tags, JS)
- Easy to integrate with other tools and libraries
- Command line tool for quick website analysis
- Fingerprints management utilities

## Installation

### Library

```bash
go get -v github.com/mamamialezatoz/go-wappalyzer@latest
```

### Command Line Tools

#### Main CLI Tool

```bash
go install -v github.com/mamamialezatoz/go-wappalyzer/cmd/go-wappalyzer@latest
```

#### Fingerprints Manager

```bash
go install -v github.com/mamamialezatoz/go-wappalyzer/cmd/fingerprints-manager@latest
```

## Usage

### As a Library (with Auto-Download)

```go
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"

	"github.com/mamamialezatoz/go-wappalyzer/pkg/wappalyzer"
)

func main() {
	// Target URL to analyze
	targetURL := "https://example.com"

	// Create an HTTP client and make a request
	resp, err := http.Get(targetURL)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	// Create a wappalyzer client - fingerprints will be auto-downloaded
	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		log.Fatal(err)
	}

	// Detect technologies
	technologies := wappalyzerClient.Fingerprint(resp.Header, body)

	// Print the results
	techNames := make([]string, 0, len(technologies))
	for name := range technologies {
		techNames = append(techNames, name)
	}
	sort.Strings(techNames)

	fmt.Println("Detected technologies:")
	for _, name := range techNames {
		fmt.Printf("- %s\n", name)
	}
	fmt.Printf("Total: %d technologies found\n", len(techNames))
}
```

### Configuring the Fingerprint Downloader

```go
// Configure the fingerprint downloader before creating the wappalyzer instance
downloaderConfig := downloader.DefaultConfig()
downloaderConfig.CacheExpiry = 12 * time.Hour  // Cache for 12 hours
downloaderConfig.ForceDownload = true          // Force a fresh download
downloaderConfig.CacheDir = "/custom/cache/dir" // Use a custom cache location
wappalyzer.SetDownloaderConfig(downloaderConfig)

// Create the wappalyzer instance
wappalyzerClient, err := wappalyzer.New()
```

### Using Advanced Features

```go
// Create with custom options
wappalyzerClient, err := wappalyzer.New(
wappalyzer.WithMaxBodySize(1024*1024), // 1MB max body size
wappalyzer.WithoutJSDetection(),       // Disable JS detection
)

// Get technology info
techInfo := wappalyzerClient.FingerprintWithInfo(resp.Header, body)

// Get technology categories
techCategories := wappalyzerClient.FingerprintWithCats(resp.Header, body)

// Analyze a URL directly
technologies, err := wappalyzerClient.AnalyzeURL("https://example.com")

// Get technologies by group
techsByGroup := wappalyzerClient.GetTechByGroup(1) // Group ID 1
```

### Command Line Usage

```bash
# Basic usage
go-wappalyzer --target https://example.com

# Force fingerprints download before analysis
go-wappalyzer --target https://example.com --force-download

# Set custom cache TTL (in hours)
go-wappalyzer --target https://example.com --cache-ttl 48

# Output as JSON
go-wappalyzer --target https://example.com --json

# Include category information
go-wappalyzer --target https://example.com --category

# Save to file
go-wappalyzer --target https://example.com --output results.txt

# Custom HTTP method and headers
go-wappalyzer --target https://example.com --method POST --header "X-Custom: Value"

# Disable SSL verification
go-wappalyzer --target https://example.com --disable-ssl

# Organize by group
go-wappalyzer --target https://example.com --by-group

# Filter by specific group
go-wappalyzer --target https://example.com --filter-group "Programming Languages"
```

### Fingerprints Manager

```bash
# Download fresh fingerprints
fingerprints-manager

# Show cache status
fingerprints-manager --status

# Clear cache
fingerprints-manager --clear

# Clear cache without re-downloading
fingerprints-manager --clear --no-download

# Use custom cache directory
fingerprints-manager --cache-dir "/tmp/wappalyzer-cache"

# Set custom cache TTL
fingerprints-manager --cache-ttl 72

# Use custom fingerprints URL
fingerprints-manager --url "https://custom-url/wappalyzer-fingerprints.zip"
```

## Auto-Download Feature

The library automatically downloads fingerprints from [ZeroCostAutomation/wappalyzer-fingerprints](https://github.com/ZeroCostAutomation/wappalyzer-fingerprints) when needed:

1. On first run, fingerprints are downloaded and cached locally
2. Cached fingerprints are used until they expire (default 24 hours)
3. After expiry, fresh fingerprints are downloaded automatically
4. Force download can be triggered if needed

The caching mechanism ensures:

- Minimal network usage
- Fast startup times after the first run
- Always up-to-date fingerprints without manual intervention
- Works offline if cached data is available

### Fingerprints File Structure

The ZeroCostAutomation/wappalyzer-fingerprints repository provides these files:

- `technologies.json`: Technology fingerprints for detection
- `categories.json`: Technology categories
- `groups.json`: Category grouping information

These files are automatically downloaded and cached in the user's cache directory.

## Project Structure

```
go-wappalyzer/
├── cmd/                          # Command line applications
│   ├── go-wappalyzer/            # Main CLI application
│   │   └── main.go
│   └── fingerprints-manager/     # Tool for managing fingerprints
│       └── main.go
├── internal/                     # Private application and library code
│   ├── detection/                # Core detection logic
│   │   ├── cookies.go            # Cookie pattern matching
│   │   ├── headers.go            # HTTP headers pattern matching
│   │   ├── html.go               # HTML content pattern matching
│   │   ├── js.go                 # JavaScript pattern matching
│   │   ├── meta.go               # Meta tag pattern matching
│   │   └── scripts.go            # Script tag pattern matching
│   ├── downloader/               # Fingerprints downloading utilities
│   │   └── downloader.go         # Auto-downloading and caching logic
│   ├── models/                   # Data structures
│   │   ├── fingerprint.go        # Fingerprint data structures
│   │   ├── patterns.go           # Pattern matching structures
│   │   └── results.go            # Result data structures
│   └── parser/                   # Parsing utilities
│       ├── compiler.go           # Fingerprints compilation
│       ├── html_parser.go        # HTML parsing utilities
│       ├── pattern.go            # Pattern parsing
│       └── regex.go              # Regular expression utilities
├── pkg/                          # Public library code
│   └── wappalyzer/               # Main package
│       ├── config.go             # Configuration options
│       └── wappalyzer.go         # Main wappalyzer functionality
├── examples/                     # Example applications
│   └── simple/
│       └── main.go               # Simple usage example
├── go.mod                        # Go module definition
└── README.md                     # Documentation
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Wappalyzer](https://github.com/AliasIO/wappalyzer) for the original implementation
- [ZeroCostAutomation/wappalyzer-fingerprints](https://github.com/ZeroCostAutomation/wappalyzer-fingerprints) for providing up-to-date fingerprint data
- [projectdiscovery/wappalyzergo](https://github.com/projectdiscovery/wappalyzergo) for the initial Go implementation