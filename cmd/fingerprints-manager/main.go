package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mamamialezatoz/go-wappalyzer/internal/downloader"
)

var (
	// Command line flags
	forceFlag      = flag.Bool("force", false, "Force download even if cache is valid")
	cacheDirFlag   = flag.String("cache-dir", "", "Custom cache directory for fingerprints")
	urlFlag        = flag.String("url", "", "Custom URL to download fingerprints from")
	cacheTTLFlag   = flag.Int("cache-ttl", 24, "Cache TTL in hours (0 for no expiry)")
	clearFlag      = flag.Bool("clear", false, "Clear the fingerprints cache")
	statusFlag     = flag.Bool("status", false, "Show status of the fingerprints cache")
	versionFlag    = flag.Bool("version", false, "Show version information")
	noDownloadFlag = flag.Bool("no-download", false, "Don't download fingerprints, just show or clear cache")
)

// Version information
const (
	Version    = "0.2.0"
	BuildDate  = "2025-10-06"
	CommitHash = "development"
)

func main() {
	flag.Parse()

	// Show version and exit if requested
	if *versionFlag {
		fmt.Printf("fingerprints-manager version %s (build: %s, commit: %s)\n",
			Version, BuildDate, CommitHash)
		os.Exit(0)
	}

	// Create a downloader config
	config := downloader.DefaultConfig()

	// Apply custom options from flags
	if *cacheDirFlag != "" {
		config.CacheDir = *cacheDirFlag
	}

	if *urlFlag != "" {
		config.ReleaseURL = *urlFlag
	}

	if *cacheTTLFlag >= 0 {
		config.CacheExpiry = time.Duration(*cacheTTLFlag) * time.Hour
	}

	config.ForceDownload = *forceFlag

	// Create cache dir if it doesn't exist
	if err := os.MkdirAll(config.CacheDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating cache directory: %v\n", err)
		os.Exit(1)
	}

	// Status flag - show cache status
	if *statusFlag {
		showCacheStatus(config)
		os.Exit(0)
	}

	// Clear flag - clear the cache
	if *clearFlag {
		clearCache(config)
		if *noDownloadFlag {
			fmt.Println("Cache cleared successfully.")
			os.Exit(0)
		}
		fmt.Println("Cache cleared. Downloading fresh fingerprints...")
	}

	// Skip download if requested
	if *noDownloadFlag {
		fmt.Println("Skipping fingerprints download as requested.")
		os.Exit(0)
	}

	// Download fingerprints
	fmt.Println("Downloading fingerprints...")
	_, _, _, err := downloader.GetFingerprints(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error downloading fingerprints: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Fingerprints downloaded and cached successfully!")
	showCacheStatus(config)
}

// clearCache removes all cached fingerprint files
func clearCache(config *downloader.Config) {
	files := []string{
		filepath.Join(config.CacheDir, "technologies.json"),
		filepath.Join(config.CacheDir, "categories.json"),
		filepath.Join(config.CacheDir, "groups.json"),
	}

	for _, file := range files {
		if _, err := os.Stat(file); err == nil {
			if err := os.Remove(file); err != nil {
				fmt.Fprintf(os.Stderr, "Error removing %s: %v\n", file, err)
			} else {
				fmt.Printf("Removed %s\n", file)
			}
		}
	}
}

// showCacheStatus displays information about the current cache
func showCacheStatus(config *downloader.Config) {
	files := []string{
		filepath.Join(config.CacheDir, "technologies.json"),
		filepath.Join(config.CacheDir, "categories.json"),
		filepath.Join(config.CacheDir, "groups.json"),
	}

	fmt.Printf("Cache directory: %s\n", config.CacheDir)
	fmt.Printf("Cache expiry: %v\n", config.CacheExpiry)
	fmt.Printf("Download URL: %s\n", config.ReleaseURL)
	fmt.Println("\nCached files:")

	allExist := true
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			fmt.Printf("  %s: Not found\n", filepath.Base(file))
			allExist = false
			continue
		}

		age := time.Since(info.ModTime())
		expiresIn := config.CacheExpiry - age
		sizeKB := float64(info.Size()) / 1024.0

		fmt.Printf("  %s: %.1f KB, modified %s ago",
			filepath.Base(file), sizeKB, formatDuration(age))

		if config.CacheExpiry > 0 {
			if expiresIn > 0 {
				fmt.Printf(" (expires in %s)", formatDuration(expiresIn))
			} else {
				fmt.Printf(" (EXPIRED)")
			}
		}
		fmt.Println()
	}

	if allExist {
		fmt.Println("\nStatus: Cache is complete")
	} else {
		fmt.Println("\nStatus: Cache is incomplete or missing")
	}
}

// formatDuration formats a duration in a human-readable format
func formatDuration(d time.Duration) string {
	if d.Hours() > 48 {
		days := int(d.Hours() / 24)
		return fmt.Sprintf("%d days", days)
	}
	if d.Hours() >= 1 {
		return fmt.Sprintf("%.1f hours", d.Hours())
	}
	if d.Minutes() >= 1 {
		return fmt.Sprintf("%.1f minutes", d.Minutes())
	}
	return fmt.Sprintf("%.1f seconds", d.Seconds())
}
