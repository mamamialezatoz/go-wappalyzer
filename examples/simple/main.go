package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/mamamialezatoz/go-wappalyzer/internal/downloader"
	"github.com/mamamialezatoz/go-wappalyzer/pkg/wappalyzer"
)

func main() {
	// Target URL to analyze
	targetURL := "https://www.example.com"

	// Configure the downloader (optional - uses defaults if not configured)
	downloaderConfig := downloader.DefaultConfig()
	downloaderConfig.CacheExpiry = 24 * time.Hour // Cache fingerprints for 24 hours
	wappalyzer.SetDownloaderConfig(downloaderConfig)

	// Create an HTTP client and make a request
	resp, err := http.Get(targetURL)
	if err != nil {
		log.Fatalf("Error making HTTP request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}

	// Create a new wappalyzer instance
	// Fingerprints will be automatically downloaded from the ZeroCostAutomation
	// repository if they aren't already cached or the cache is expired
	w, err := wappalyzer.New()
	if err != nil {
		log.Fatalf("Error creating wappalyzer instance: %v", err)
	}

	// Detect technologies with basic information
	technologies := w.FingerprintWithInfo(resp.Header, body)

	// Sort technology names for consistent output
	names := make([]string, 0, len(technologies))
	for name := range technologies {
		names = append(names, name)
	}
	sort.Strings(names)

	// Print detected technologies
	fmt.Printf("Detected technologies on %s:\n", targetURL)
	fmt.Println(strings.Repeat("-", 40))

	for _, name := range names {
		info := technologies[name]
		fmt.Printf("- %s\n", name)

		if info.Description != "" {
			fmt.Printf("  Description: %s\n", info.Description)
		}

		if info.Website != "" {
			fmt.Printf("  Website: %s\n", info.Website)
		}

		fmt.Println()
	}

	fmt.Printf("Total: %d technologies detected\n", len(technologies))
}
