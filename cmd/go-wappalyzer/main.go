package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/mamamialezatoz/go-wappalyzer/internal/downloader"
	"github.com/mamamialezatoz/go-wappalyzer/internal/models"
	"github.com/mamamialezatoz/go-wappalyzer/pkg/wappalyzer"
)

// HeaderFlags allows for multiple -header flags
type HeaderFlags []string

func (h *HeaderFlags) String() string {
	return strings.Join(*h, ", ")
}

func (h *HeaderFlags) Set(value string) error {
	*h = append(*h, value)
	return nil
}

var (
	// Command line flags
	targetFlag         = flag.String("target", "", "Target URL to analyze")
	outputFlag         = flag.String("output", "", "Output file path")
	methodFlag         = flag.String("method", "GET", "HTTP method to use")
	jsonFlag           = flag.Bool("json", false, "Output in JSON format")
	noColorFlag        = flag.Bool("no-color", false, "Disable colored output")
	silentFlag         = flag.Bool("silent", false, "Don't display any output")
	versionFlag        = flag.Bool("version", false, "Show version information")
	disableSSLFlag     = flag.Bool("disable-ssl", false, "Don't verify SSL certificates")
	categoryFlag       = flag.Bool("category", false, "Include category information")
	groupFlag          = flag.Bool("group", false, "Include group information")
	byGroupFlag        = flag.Bool("by-group", false, "Organize results by group")
	listGroupsFlag     = flag.Bool("list-groups", false, "List all available groups and exit")
	listCategoriesFlag = flag.Bool("list-categories", false, "List all available categories and exit")
	filterGroupFlag    = flag.String("filter-group", "", "Filter results to show only technologies in the specified group")
	timeoutFlag        = flag.Int("timeout", 10, "Timeout in seconds for HTTP requests")
	maxBodySizeFlag    = flag.Int("max-body-size", 0, "Maximum response body size to analyze (0 = no limit)")
	fingerprintURLFlag = flag.String("fingerprint-url", "", "Custom URL to download fingerprints from")
	cacheTTLFlag       = flag.Int("cache-ttl", 24, "Cache TTL in hours (0 for no expiry)")
	cacheDirFlag       = flag.String("cache-dir", "", "Custom cache directory for fingerprints")
	forceDownloadFlag  = flag.Bool("force-download", false, "Force download of fingerprints even if cache is valid")
	customHeaders      HeaderFlags
)

// Version information
const (
	Version    = "0.2.0"
	BuildDate  = "2025-10-05"
	CommitHash = "development"
)

// parseHeaders parses header flags into a map
func parseHeaders(headerFlags []string) map[string]string {
	headers := make(map[string]string)
	for _, h := range headerFlags {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return headers
}

// colorize applies color to text if enabled
func colorize(text, color string, enabled bool) string {
	if enabled {
		return color + text + "\033[0m"
	}
	return text
}

// listAvailableGroups prints all available groups
func listAvailableGroups() {
	groups := wappalyzer.GetGroupsMapping()

	// Sort group IDs
	groupIDs := make([]int, 0, len(groups))
	for id := range groups {
		groupIDs = append(groupIDs, id)
	}
	sort.Ints(groupIDs)

	fmt.Println("Available Fingerprint Groups:")
	fmt.Println("============================")

	for _, id := range groupIDs {
		group := groups[id]
		fmt.Printf("Group %d: %s\n", id, group.Name)
	}
}

// listAvailableCategories prints all available categories
func listAvailableCategories() {
	categories := wappalyzer.GetCategoriesMapping()
	groups := wappalyzer.GetGroupsMapping()

	// Sort category IDs
	categoryIDs := make([]int, 0, len(categories))
	for id := range categories {
		categoryIDs = append(categoryIDs, id)
	}
	sort.Ints(categoryIDs)

	fmt.Println("Available Fingerprint Categories:")
	fmt.Println("===============================")

	for _, id := range categoryIDs {
		category := categories[id]

		// Get group names for this category
		groupNames := make([]string, 0, len(category.Groups))
		for _, groupID := range category.Groups {
			if group, ok := groups[groupID]; ok {
				groupNames = append(groupNames, group.Name)
			}
		}

		fmt.Printf("Category %d: %s\n", id, category.Name)
		fmt.Printf("  Priority: %d\n", category.Priority)

		if len(groupNames) > 0 {
			fmt.Printf("  Groups: %s\n", strings.Join(groupNames, ", "))
		}
		fmt.Println()
	}
}

// findGroupIDByName finds the group ID for a given group name
func findGroupIDByName(name string) (int, bool) {
	groups := wappalyzer.GetGroupsMapping()
	nameLower := strings.ToLower(name)

	for id, group := range groups {
		if strings.ToLower(group.Name) == nameLower {
			return id, true
		}
	}

	return 0, false
}

func main() {
	// Set up flags
	flag.Var(&customHeaders, "header", "HTTP headers to include (can be used multiple times)")
	flag.Parse()

	// Show version and exit if requested
	if *versionFlag {
		fmt.Printf("go-wappalyzer version %s (build: %s, commit: %s)\n", Version, BuildDate, CommitHash)
		os.Exit(0)
	}

	// Configure the fingerprints downloader
	downloaderConfig := downloader.DefaultConfig()
	if *fingerprintURLFlag != "" {
		downloaderConfig.ReleaseURL = *fingerprintURLFlag
	}
	if *cacheDirFlag != "" {
		downloaderConfig.CacheDir = *cacheDirFlag
	}
	if *cacheTTLFlag >= 0 {
		downloaderConfig.CacheExpiry = time.Duration(*cacheTTLFlag) * time.Hour
	}
	downloaderConfig.ForceDownload = *forceDownloadFlag

	// Set the downloader config
	wappalyzer.SetDownloaderConfig(downloaderConfig)

	// List groups if requested
	if *listGroupsFlag {
		listAvailableGroups()
		os.Exit(0)
	}

	// List categories if requested
	if *listCategoriesFlag {
		listAvailableCategories()
		os.Exit(0)
	}

	// Validate required flags
	if *targetFlag == "" {
		flag.Usage()
		fmt.Println("\nError: target URL is required")
		os.Exit(1)
	}

	// Create HTTP transport with SSL verification option
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: *disableSSLFlag,
		},
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(*timeoutFlag) * time.Second,
	}

	// Ensure target has a scheme
	target := *targetFlag
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	// Create request
	req, err := http.NewRequest(*methodFlag, target, nil)
	if err != nil {
		log.Fatalf("Error creating request: %v", err)
	}

	// Add headers
	headers := parseHeaders(customHeaders)
	for name, value := range headers {
		req.Header.Set(name, value)
	}

	// Set User-Agent if not provided
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", fmt.Sprintf("go-wappalyzer/%s", Version))
	}

	// Make the request
	if !*silentFlag {
		fmt.Printf("Analyzing %s...\n", target)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error making request: %v", err)
	}
	defer resp.Body.Close()

	// Limit the body size if configured
	var reader io.Reader = resp.Body
	if *maxBodySizeFlag > 0 {
		reader = io.LimitReader(resp.Body, int64(*maxBodySizeFlag))
	}

	// Read the response body
	body, err := io.ReadAll(reader)
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}

	// Create wappalyzer instance
	options := []wappalyzer.Option{
		wappalyzer.WithAllDetections(),
	}

	if *maxBodySizeFlag > 0 {
		options = append(options, wappalyzer.WithMaxBodySize(*maxBodySizeFlag))
	}

	w, err := wappalyzer.New(options...)
	if err != nil {
		log.Fatalf("Error creating wappalyzer instance: %v", err)
	}

	// Detect technologies
	var results interface{}

	// If filtering by group
	if *filterGroupFlag != "" {
		groupID, found := findGroupIDByName(*filterGroupFlag)
		if !found {
			log.Fatalf("Error: Group '%s' not found", *filterGroupFlag)
		}

		// Get technologies by group
		techs := w.GetTechByGroup(groupID)

		// Create a map for output
		techMap := make(map[string]struct{})
		for _, tech := range techs {
			techMap[tech] = struct{}{}
		}

		// Get additional information if needed
		if *categoryFlag || *groupFlag {
			techInfo := make(map[string]interface{})

			if *categoryFlag {
				catInfo := w.FingerprintWithCats(resp.Header, body)
				for tech := range techMap {
					if info, ok := catInfo[tech]; ok {
						techInfo[tech] = info
					}
				}
				results = techInfo
			} else if *groupFlag {
				groupInfo := w.FingerprintWithGroups(resp.Header, body)
				for tech := range techMap {
					if info, ok := groupInfo[tech]; ok {
						techInfo[tech] = info
					}
				}
				results = techInfo
			} else {
				results = techMap
			}
		} else {
			results = techMap
		}
	} else if *byGroupFlag {
		// Organize results by group
		results = w.FingerprintWithGroups(resp.Header, body)
	} else if *categoryFlag && *groupFlag {
		// If both category and group info are requested, use comprehensive info
		results = w.FingerprintWithTechInfo(resp.Header, body)
	} else if *categoryFlag {
		// Just category information
		results = w.FingerprintWithCats(resp.Header, body)
	} else if *groupFlag {
		// Just group information
		results = w.FingerprintWithGroups(resp.Header, body)
	} else {
		// Basic information
		results = w.FingerprintWithInfo(resp.Header, body)
	}

	// Format and output results
	if *jsonFlag {
		// JSON output
		output, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			log.Fatalf("Error formatting JSON output: %v", err)
		}

		if *outputFlag != "" {
			// Write to file
			err = os.WriteFile(*outputFlag, output, 0644)
			if err != nil {
				log.Fatalf("Error writing output to file: %v", err)
			}
			if !*silentFlag {
				fmt.Printf("Results written to %s\n", *outputFlag)
			}
		} else if !*silentFlag {
			// Write to stdout
			fmt.Println(string(output))
		}
	} else {
		// Text output
		var output strings.Builder

		// Colorization
		useColors := !*noColorFlag && *outputFlag == ""
		colors := map[string]string{
			"tech":      "\033[1;36m", // Cyan
			"desc":      "\033[0;37m", // Light gray
			"website":   "\033[0;33m", // Yellow
			"cat":       "\033[0;32m", // Green
			"group":     "\033[0;35m", // Purple
			"header":    "\033[1;35m", // Magenta
			"subheader": "\033[1;33m", // Yellow bold
		}

		// Different output formats based on results type
		switch typedResults := results.(type) {
		case map[string]wappalyzer.TechInfo:
			// Comprehensive tech info
			techNames := make([]string, 0, len(typedResults))
			for tech := range typedResults {
				techNames = append(techNames, tech)
			}
			sort.Strings(techNames)

			// If organizing by group
			if *byGroupFlag {
				// Create a map of group to technologies
				groupToTechs := make(map[string][]string)

				for _, tech := range techNames {
					info := typedResults[tech]

					if len(info.Groups) == 0 {
						groupToTechs["Uncategorized"] = append(groupToTechs["Uncategorized"], tech)
					} else {
						for _, group := range info.Groups {
							groupToTechs[group] = append(groupToTechs[group], tech)
						}
					}
				}

				// Get sorted group names
				groupNames := make([]string, 0, len(groupToTechs))
				for group := range groupToTechs {
					groupNames = append(groupNames, group)
				}
				sort.Strings(groupNames)

				// Output by group
				output.WriteString(colorize(fmt.Sprintf("Detected %d technologies in %d groups:\n", len(techNames), len(groupNames)), colors["header"], useColors))
				output.WriteString("=======================================\n\n")

				for _, group := range groupNames {
					techs := groupToTechs[group]
					sort.Strings(techs)

					output.WriteString(colorize(fmt.Sprintf("Group: %s (%d technologies)\n", group, len(techs)), colors["subheader"], useColors))
					output.WriteString("---------------------------\n")

					for _, tech := range techs {
						info := typedResults[tech]

						output.WriteString(colorize(tech+":", colors["tech"], useColors) + "\n")

						if info.Description != "" {
							output.WriteString(colorize("  Description: ", colors["desc"], useColors) + info.Description + "\n")
						}
						if info.Website != "" {
							output.WriteString(colorize("  Website: ", colors["website"], useColors) + info.Website + "\n")
						}
						if len(info.Categories) > 0 {
							output.WriteString(colorize("  Categories: ", colors["cat"], useColors) + strings.Join(info.Categories, ", ") + "\n")
						}

						output.WriteString("\n")
					}

					output.WriteString("\n")
				}
			} else {
				// Regular output by technology
				output.WriteString(colorize(fmt.Sprintf("Detected %d technologies:\n", len(techNames)), colors["header"], useColors))
				output.WriteString("=======================\n\n")

				for _, tech := range techNames {
					info := typedResults[tech]

					output.WriteString(colorize(tech+":", colors["tech"], useColors) + "\n")

					if info.Description != "" {
						output.WriteString(colorize("  Description: ", colors["desc"], useColors) + info.Description + "\n")
					}
					if info.Website != "" {
						output.WriteString(colorize("  Website: ", colors["website"], useColors) + info.Website + "\n")
					}
					if len(info.Categories) > 0 {
						output.WriteString(colorize("  Categories: ", colors["cat"], useColors) + strings.Join(info.Categories, ", ") + "\n")
					}
					if len(info.Groups) > 0 {
						output.WriteString(colorize("  Groups: ", colors["group"], useColors) + strings.Join(info.Groups, ", ") + "\n")
					}

					output.WriteString("\n")
				}
			}

		case map[string]models.AppInfo:
			techNames := make([]string, 0, len(typedResults))
			for tech := range typedResults {
				techNames = append(techNames, tech)
			}
			sort.Strings(techNames)

			for _, tech := range techNames {
				info := typedResults[tech]
				output.WriteString(colorize(tech+":", colors["tech"], useColors) + "\n")

				if info.Description != "" {
					output.WriteString(colorize("  Description: ", colors["desc"], useColors) + info.Description + "\n")
				}
				if info.Website != "" {
					output.WriteString(colorize("  Website: ", colors["website"], useColors) + info.Website + "\n")
				}
				output.WriteString("\n")
			}

		case map[string]models.CatsInfo:
			techNames := make([]string, 0, len(typedResults))
			for tech := range typedResults {
				techNames = append(techNames, tech)
			}
			sort.Strings(techNames)

			for _, tech := range techNames {
				info := typedResults[tech]
				output.WriteString(colorize(tech+":", colors["tech"], useColors) + "\n")

				if len(info.Cats) > 0 {
					categoryNames := make([]string, 0, len(info.Cats))
					categories := wappalyzer.GetCategoriesMapping()

					for _, catID := range info.Cats {
						if category, ok := categories[catID]; ok {
							categoryNames = append(categoryNames, category.Name)
						} else {
							categoryNames = append(categoryNames, fmt.Sprintf("Category %d", catID))
						}
					}
					output.WriteString(colorize("  Categories: ", colors["cat"], useColors) + strings.Join(categoryNames, ", ") + "\n")
				}
				output.WriteString("\n")
			}

		case map[string][]string: // FingerprintWithGroups or FingerprintWithCategories
			techNames := make([]string, 0, len(typedResults))
			for tech := range typedResults {
				techNames = append(techNames, tech)
			}
			sort.Strings(techNames)

			if *byGroupFlag {
				// Organize by group
				groupToTechs := make(map[string][]string)

				for tech, groups := range typedResults {
					if len(groups) == 0 {
						groupToTechs["Uncategorized"] = append(groupToTechs["Uncategorized"], tech)
					} else {
						for _, group := range groups {
							groupToTechs[group] = append(groupToTechs[group], tech)
						}
					}
				}

				groupNames := make([]string, 0, len(groupToTechs))
				for group := range groupToTechs {
					groupNames = append(groupNames, group)
				}
				sort.Strings(groupNames)

				output.WriteString(colorize(fmt.Sprintf("Detected %d technologies in %d groups:\n", len(techNames), len(groupNames)), colors["header"], useColors))
				output.WriteString("=======================================\n\n")

				for _, group := range groupNames {
					techs := groupToTechs[group]
					sort.Strings(techs)

					output.WriteString(colorize(fmt.Sprintf("Group: %s (%d technologies)\n", group, len(techs)), colors["subheader"], useColors))
					output.WriteString("---------------------------\n")

					for _, tech := range techs {
						output.WriteString(colorize("• "+tech, colors["tech"], useColors) + "\n")
					}

					output.WriteString("\n")
				}
			} else {
				// Regular output
				for _, tech := range techNames {
					values := typedResults[tech]
					output.WriteString(colorize(tech+":", colors["tech"], useColors) + "\n")

					if len(values) > 0 {
						if *categoryFlag {
							output.WriteString(colorize("  Categories: ", colors["cat"], useColors) + strings.Join(values, ", ") + "\n")
						} else if *groupFlag {
							output.WriteString(colorize("  Groups: ", colors["group"], useColors) + strings.Join(values, ", ") + "\n")
						}
					} else {
						if *categoryFlag {
							output.WriteString(colorize("  Categories: ", colors["cat"], useColors) + "None\n")
						} else if *groupFlag {
							output.WriteString(colorize("  Groups: ", colors["group"], useColors) + "None\n")
						}
					}
					output.WriteString("\n")
				}
			}

		case map[string]struct{}:
			techNames := make([]string, 0, len(typedResults))
			for tech := range typedResults {
				techNames = append(techNames, tech)
			}
			sort.Strings(techNames)

			for _, tech := range techNames {
				output.WriteString(colorize(tech, colors["tech"], useColors) + "\n")
			}
		}

		if *outputFlag != "" {
			// Write to file
			err = os.WriteFile(*outputFlag, []byte(output.String()), 0644)
			if err != nil {
				log.Fatalf("Error writing output to file: %v", err)
			}
			if !*silentFlag {
				fmt.Printf("Results written to %s\n", *outputFlag)
			}
		} else if !*silentFlag {
			// Write to stdout
			fmt.Print(output.String())

			// Show result count
			var count int
			switch typedResults := results.(type) {
			case map[string]wappalyzer.TechInfo:
				count = len(typedResults)
			case map[string]models.AppInfo:
				count = len(typedResults)
			case map[string]models.CatsInfo:
				count = len(typedResults)
			case map[string][]string:
				count = len(typedResults)
			case map[string]struct{}:
				count = len(typedResults)
			}
			fmt.Printf("Found %d technologies\n", count)
		}
	}
}
