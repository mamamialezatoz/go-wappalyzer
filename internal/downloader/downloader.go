package downloader

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	// DefaultLatestReleaseURL is the URL to the latest release of the wappalyzer-fingerprints
	DefaultLatestReleaseURL = "https://github.com/ZeroCostAutomation/wappalyzer-fingerprints/releases/latest/download/wappalyzer-fingerprints.zip"

	// DefaultCacheDir is the default directory where fingerprints are cached
	DefaultCacheDir = ".cache/go-wappalyzer"

	// DefaultCacheExpiry is the default expiry time for cached fingerprints
	DefaultCacheExpiry = 24 * time.Hour
)

// Config contains configuration for the fingerprints downloader
type Config struct {
	// ReleaseURL is the URL to download the fingerprints from
	ReleaseURL string

	// CacheDir is the directory where fingerprints are cached
	CacheDir string

	// CacheExpiry is how long to keep cached fingerprints before re-downloading
	CacheExpiry time.Duration

	// ForceDownload forces a new download even if cache is valid
	ForceDownload bool

	// DisableCache disables caching altogether
	DisableCache bool

	// Client is the HTTP client to use for downloads
	Client *http.Client
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		ReleaseURL:    DefaultLatestReleaseURL,
		CacheDir:      filepath.Join(userCacheDir(), DefaultCacheDir),
		CacheExpiry:   DefaultCacheExpiry,
		ForceDownload: false,
		DisableCache:  false,
		Client:        http.DefaultClient,
	}
}

// userCacheDir returns the user's cache directory
func userCacheDir() string {
	// Try to use the OS-specific cache directory
	cacheDir, err := os.UserCacheDir()
	if err == nil {
		return cacheDir
	}

	// Fallback to home directory
	homeDir, err := os.UserHomeDir()
	if err == nil {
		return filepath.Join(homeDir, ".cache")
	}

	// Last resort, use temporary directory
	return os.TempDir()
}

// LoadTechnologiesFile loads and parses the technologies.json file, handling both array and object formats
func LoadTechnologiesFile(path string) (map[string]json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	// First try to parse as an object (original format)
	var objResult map[string]json.RawMessage
	if err := json.Unmarshal(data, &objResult); err == nil {
		return objResult, nil
	}

	// If that fails, try to parse as an array (new format)
	var arrayResult []json.RawMessage
	if err := json.Unmarshal(data, &arrayResult); err != nil {
		return nil, fmt.Errorf("failed to parse JSON as either object or array: %v", err)
	}

	// Convert the array to the object format expected by the rest of the code
	result := make(map[string]json.RawMessage)
	for _, item := range arrayResult {
		var tech struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(item, &tech); err == nil && tech.Name != "" {
			result[tech.Name] = item
		}
	}

	return result, nil
}

// loadJSONFile loads a JSON file and returns its contents as a map
func loadJSONFile(path string) (map[string]json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	return result, nil
}

// GetFingerprints downloads and returns the fingerprints data
func GetFingerprints(config *Config) (map[string]json.RawMessage, map[string]json.RawMessage, map[string]json.RawMessage, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Create cache directory if it doesn't exist and caching is enabled
	if !config.DisableCache {
		if err := os.MkdirAll(config.CacheDir, 0755); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to create cache directory: %v", err)
		}
	}

	// Check if we need to download
	needsDownload := true
	if !config.DisableCache && !config.ForceDownload {
		// Check if we have valid cached files
		technologiesPath := filepath.Join(config.CacheDir, "technologies.json")
		catsPath := filepath.Join(config.CacheDir, "categories.json")
		groupsPath := filepath.Join(config.CacheDir, "groups.json")

		if fileExists(technologiesPath) && fileExists(catsPath) && fileExists(groupsPath) {
			// Check if files are recent enough
			technologiesInfo, err := os.Stat(technologiesPath)
			if err == nil && time.Since(technologiesInfo.ModTime()) < config.CacheExpiry {
				needsDownload = false
			}
		}
	}

	// Download if needed
	if needsDownload {
		if err := downloadAndExtractFingerprints(config); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to download fingerprints: %v", err)
		}
	}

	// Load the fingerprints
	technologies, err := LoadTechnologiesFile(filepath.Join(config.CacheDir, "technologies.json"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load technologies data: %v", err)
	}

	categories, err := loadJSONFile(filepath.Join(config.CacheDir, "categories.json"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load categories data: %v", err)
	}

	groups, err := loadJSONFile(filepath.Join(config.CacheDir, "groups.json"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load groups data: %v", err)
	}

	return technologies, categories, groups, nil
}

// downloadAndExtractFingerprints downloads and extracts the fingerprints
func downloadAndExtractFingerprints(config *Config) error {
	// Download the zip file
	resp, err := config.Client.Get(config.ReleaseURL)
	if err != nil {
		return fmt.Errorf("failed to download fingerprints: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Read the zip data
	zipData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	// Open the zip archive
	zipReader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return fmt.Errorf("failed to open zip archive: %v", err)
	}

	// Extract required files
	for _, file := range zipReader.File {
		var destPath string
		switch filepath.Base(file.Name) {
		case "technologies.json", "categories.json", "groups.json":
			destPath = filepath.Join(config.CacheDir, filepath.Base(file.Name))
		default:
			continue // Skip other files
		}

		// Open the file in the zip
		rc, err := file.Open()
		if err != nil {
			return fmt.Errorf("failed to open file %s in zip: %v", file.Name, err)
		}

		// Create the destination file
		destFile, err := os.Create(destPath)
		if err != nil {
			rc.Close()
			return fmt.Errorf("failed to create file %s: %v", destPath, err)
		}

		// Copy the contents
		_, err = io.Copy(destFile, rc)
		rc.Close()
		destFile.Close()
		if err != nil {
			return fmt.Errorf("failed to extract file %s: %v", file.Name, err)
		}
	}

	return nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
