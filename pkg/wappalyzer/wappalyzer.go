// Package wappalyzer provides functionality for detecting web technologies
// based on HTTP response data.
package wappalyzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/mamamialezatoz/go-wappalyzer/internal/detection"
	"github.com/mamamialezatoz/go-wappalyzer/internal/downloader"
	"github.com/mamamialezatoz/go-wappalyzer/internal/models"
	"github.com/mamamialezatoz/go-wappalyzer/internal/parser"
)

// CategoryItem contains information about a technology category
type CategoryItem struct {
	Name     string `json:"name"`
	Priority int    `json:"priority"`
	Groups   []int  `json:"groups"` // Groups that this category belongs to
}

// GroupItem contains information about a technology group
type GroupItem struct {
	Name string `json:"name"`
}

// TechInfo provides comprehensive information about a detected technology
type TechInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Website     string   `json:"website"`
	CPE         string   `json:"cpe,omitempty"`
	Categories  []string `json:"categories,omitempty"`
	Groups      []string `json:"groups,omitempty"`
	Confidence  int      `json:"confidence,omitempty"`
	Version     string   `json:"version,omitempty"`
}

var (
	syncOnce          sync.Once
	categoriesMapping map[int]CategoryItem
	groupsMapping     map[int]GroupItem
	categoryToGroups  map[int][]int // Mapping from category ID to group IDs
	groupCategories   map[int][]int // Mapping from group ID to category IDs

	// downloaderConfig holds the configuration for the fingerprints downloader
	downloaderConfig *downloader.Config
)

// Wappalyze is a client for working with technology detection
type Wappalyze struct {
	config            *Config
	fingerprints      *models.CompiledFingerprints
	headerPatterns    map[string]map[string]*models.ParsedPattern
	cookiePatterns    map[string]map[string]*models.ParsedPattern
	htmlPatterns      map[string][]*models.ParsedPattern
	scriptPatterns    map[string][]*models.ParsedPattern
	scriptSrcPatterns map[string][]*models.ParsedPattern
	metaPatterns      map[string]map[string][]*models.ParsedPattern
	jsPatterns        map[string]map[string]*models.ParsedPattern
	impliesMapping    map[string][]string
	categoryMapping   map[string][]int
}

// SetDownloaderConfig sets the global configuration for the fingerprints downloader
func SetDownloaderConfig(config *downloader.Config) {
	downloaderConfig = config
}

func loadDataOnce() error {
	var err error
	syncOnce.Do(func() {
		categoriesMapping = make(map[int]CategoryItem)
		groupsMapping = make(map[int]GroupItem)
		categoryToGroups = make(map[int][]int)
		groupCategories = make(map[int][]int)

		// Download and load data from ZeroCostAutomation/wappalyzer-fingerprints
		config := downloaderConfig
		if config == nil {
			config = downloader.DefaultConfig()
		}

		// Get the fingerprints data
		_, categoriesData, groupsData, err := downloader.GetFingerprints(config)
		if err != nil {
			err = fmt.Errorf("failed to get fingerprints data: %v", err)
			return
		}

		// Process categories data
		for categoryIDStr, rawData := range categoriesData {
			var categoryData map[string]json.RawMessage
			if err = json.Unmarshal(rawData, &categoryData); err != nil {
				continue
			}

			category := CategoryItem{}

			// Extract name
			if nameData, ok := categoryData["name"]; ok {
				json.Unmarshal(nameData, &category.Name)
			}

			// Extract priority
			if priorityData, ok := categoryData["priority"]; ok {
				json.Unmarshal(priorityData, &category.Priority)
			}

			// Extract groups
			if groupsData, ok := categoryData["groups"]; ok {
				var groups []int
				json.Unmarshal(groupsData, &groups)
				category.Groups = groups
			}

			// Convert category ID to int
			categoryID, err := strconv.Atoi(categoryIDStr)
			if err != nil {
				continue
			}

			// Store in mapping
			categoriesMapping[categoryID] = category

			// Build category to groups mapping
			if len(category.Groups) > 0 {
				categoryToGroups[categoryID] = category.Groups

				// Also build reverse mapping (group to categories)
				for _, groupID := range category.Groups {
					groupCategories[groupID] = append(groupCategories[groupID], categoryID)
				}
			}
		}

		// Process groups data
		for groupIDStr, rawData := range groupsData {
			var group GroupItem
			if err = json.Unmarshal(rawData, &group); err != nil {
				continue
			}

			groupID, err := strconv.Atoi(groupIDStr)
			if err != nil {
				continue
			}

			groupsMapping[groupID] = group
		}
	})
	return err
}

// New creates a new technology detection instance
func New(options ...Option) (*Wappalyze, error) {
	// Load the categories and groups data
	if err := loadDataOnce(); err != nil {
		return nil, err
	}

	// Default config
	config := &Config{}

	// Apply options
	for _, option := range options {
		option(config)
	}

	// Get fingerprints data
	var fingerprintsData []byte
	var err error

	if config.JSON != nil && len(config.JSON) > 0 {
		// Use provided fingerprints data
		fingerprintsData = config.JSON
	} else {
		// Download and get the fingerprints data
		dlConfig := downloaderConfig
		if dlConfig == nil {
			dlConfig = downloader.DefaultConfig()
		}

		// Get the fingerprints data
		technologiesData, _, _, err := downloader.GetFingerprints(dlConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to get fingerprints data: %v", err)
		}

		// Convert the technologies data to the expected format
		fingerprints := &models.Fingerprints{
			Apps: make(map[string]*models.Fingerprint),
		}

		// Process the technologies data
		for appName, rawData := range technologiesData {
			var app models.Fingerprint
			if err = json.Unmarshal(rawData, &app); err != nil {
				return nil, fmt.Errorf("failed to parse fingerprint data for %s: %v", appName, err)
			}

			// Ensure name is set (should already be in new format, but just to be safe)
			if app.Name == "" {
				app.Name = appName
			}

			// Process JS values to ensure they're all strings
			if app.JS != nil {
				app.JS = processJSValues(app.JS)
			}

			fingerprints.Apps[appName] = &app
		}

		// Marshal the fingerprints to JSON
		fingerprintsData, err = json.Marshal(fingerprints)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal fingerprints: %v", err)
		}
	}

	// Parse fingerprints from JSON
	var fingerprints models.Fingerprints
	err = json.NewDecoder(bytes.NewReader(fingerprintsData)).Decode(&fingerprints)
	if err != nil {
		return nil, fmt.Errorf("could not decode fingerprints: %v", err)
	}

	wappalyze := &Wappalyze{
		config:            config,
		headerPatterns:    make(map[string]map[string]*models.ParsedPattern),
		cookiePatterns:    make(map[string]map[string]*models.ParsedPattern),
		htmlPatterns:      make(map[string][]*models.ParsedPattern),
		scriptPatterns:    make(map[string][]*models.ParsedPattern),
		scriptSrcPatterns: make(map[string][]*models.ParsedPattern),
		metaPatterns:      make(map[string]map[string][]*models.ParsedPattern),
		jsPatterns:        make(map[string]map[string]*models.ParsedPattern),
		impliesMapping:    make(map[string][]string),
		categoryMapping:   make(map[string][]int),
	}

	// Compile fingerprints
	compiledFingerprints, err := parser.CompileFingerprints(&fingerprints)
	if err != nil {
		return nil, fmt.Errorf("could not compile fingerprints: %v", err)
	}
	wappalyze.fingerprints = compiledFingerprints

	// Extract and organize patterns
	if err := wappalyze.organizePatterns(); err != nil {
		return nil, fmt.Errorf("failed to organize patterns: %v", err)
	}

	// Build implies mapping
	wappalyze.buildImpliesMapping()

	// Build category mapping
	wappalyze.buildCategoryMapping()

	return wappalyze, nil
}

// processJSValues converts JS property values to strings
func processJSValues(js interface{}) map[string]string {
	if js == nil {
		return nil
	}

	result := make(map[string]string)

	switch jsData := js.(type) {
	case map[string]string:
		// Already in the expected format
		return jsData
	case map[string]interface{}:
		for key, value := range jsData {
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
				// For complex objects, just use an empty pattern
				result[key] = ""
			}
		}
	}

	return result
}

// NewWithCustomFingerprints creates a new technology detection instance with custom fingerprints
func NewWithCustomFingerprints(fingerprintsJSON []byte) (*Wappalyze, error) {
	return New(WithCustomFingerprints(fingerprintsJSON))
}

// GetCompiledFingerprints returns the compiled fingerprints
func (w *Wappalyze) GetCompiledFingerprints() *models.CompiledFingerprints {
	return w.fingerprints
}

// GetCategoriesMapping returns the categories mapping
func GetCategoriesMapping() map[int]CategoryItem {
	loadDataOnce()
	return categoriesMapping
}

// GetGroupsMapping returns the groups mapping
func GetGroupsMapping() map[int]GroupItem {
	loadDataOnce()
	return groupsMapping
}

// GetCategoryGroups returns the groups associated with a category
func GetCategoryGroups(categoryID int) []int {
	loadDataOnce()
	return categoryToGroups[categoryID]
}

// GetGroupCategories returns the categories associated with a group
func GetGroupCategories(groupID int) []int {
	loadDataOnce()
	return groupCategories[groupID]
}

// Fingerprint identifies technologies on a target, based on
// the received response headers and body.
//
// Body should not be mutated while this function is being called,
// or it may lead to unexpected results.
func (w *Wappalyze) Fingerprint(headers map[string][]string, body []byte) map[string]struct{} {
	technologies := make(map[string]struct{})

	// Match all the technologies based on the data we have
	w.detectTechnologies(headers, body, technologies)

	// Get implied technologies
	w.addImpliedTechnologies(technologies)

	return technologies
}

// FingerprintWithInfo identifies technologies on a target and returns
// additional information about each detected technology.
func (w *Wappalyze) FingerprintWithInfo(headers map[string][]string, body []byte) map[string]models.AppInfo {
	technologies := make(map[string]struct{})
	w.detectTechnologies(headers, body, technologies)
	w.addImpliedTechnologies(technologies)

	result := make(map[string]models.AppInfo)
	for technology := range technologies {
		if app, ok := w.fingerprints.Apps[technology]; ok {
			info := models.AppInfo{
				Description: app.Description,
				Website:     app.Website,
			}
			result[technology] = info
		} else {
			result[technology] = models.AppInfo{}
		}
	}
	return result
}

// FingerprintWithCats identifies technologies on a target and returns
// additional category information about each detected technology.
func (w *Wappalyze) FingerprintWithCats(headers map[string][]string, body []byte) map[string]models.CatsInfo {
	technologies := make(map[string]struct{})
	w.detectTechnologies(headers, body, technologies)
	w.addImpliedTechnologies(technologies)

	result := make(map[string]models.CatsInfo)
	for technology := range technologies {
		cats, ok := w.categoryMapping[technology]
		if !ok {
			result[technology] = models.CatsInfo{}
			continue
		}
		result[technology] = models.CatsInfo{Cats: cats}
	}
	return result
}

// FingerprintWithTitle identifies technologies on a target and returns
// the title of the page along with the technologies.
func (w *Wappalyze) FingerprintWithTitle(headers map[string][]string, body []byte) (map[string]struct{}, string) {
	technologies := w.Fingerprint(headers, body)
	title := parser.ExtractTitle(body)
	return technologies, title
}

// FingerprintWithCategories identifies technologies on a target and returns
// additional human-readable category information about each detected technology.
func (w *Wappalyze) FingerprintWithCategories(headers map[string][]string, body []byte) map[string][]string {
	technologies := make(map[string]struct{})
	w.detectTechnologies(headers, body, technologies)
	w.addImpliedTechnologies(technologies)

	result := make(map[string][]string)
	for technology := range technologies {
		catIDs, ok := w.categoryMapping[technology]
		if !ok {
			result[technology] = []string{}
			continue
		}

		catNames := make([]string, 0, len(catIDs))
		for _, catID := range catIDs {
			if cat, ok := categoriesMapping[catID]; ok {
				catNames = append(catNames, cat.Name)
			}
		}
		result[technology] = catNames
	}
	return result
}

// FingerprintWithGroups identifies technologies on a target and returns
// additional human-readable group information about each detected technology.
func (w *Wappalyze) FingerprintWithGroups(headers map[string][]string, body []byte) map[string][]string {
	technologies := make(map[string]struct{})
	w.detectTechnologies(headers, body, technologies)
	w.addImpliedTechnologies(technologies)

	result := make(map[string][]string)
	for technology := range technologies {
		catIDs, ok := w.categoryMapping[technology]
		if !ok {
			result[technology] = []string{}
			continue
		}

		// Collect all unique group IDs for this technology's categories
		groupIDsMap := make(map[int]struct{})
		for _, catID := range catIDs {
			if groupIDs, ok := categoryToGroups[catID]; ok {
				for _, groupID := range groupIDs {
					groupIDsMap[groupID] = struct{}{}
				}
			}
		}

		// Convert group IDs to names
		groupNames := make([]string, 0, len(groupIDsMap))
		for groupID := range groupIDsMap {
			if group, ok := groupsMapping[groupID]; ok {
				groupNames = append(groupNames, group.Name)
			}
		}

		result[technology] = groupNames
	}
	return result
}

// FingerprintWithTechInfo identifies technologies on a target and returns
// comprehensive information including categories and groups.
func (w *Wappalyze) FingerprintWithTechInfo(headers map[string][]string, body []byte) map[string]TechInfo {
	technologies := make(map[string]struct{})
	w.detectTechnologies(headers, body, technologies)
	w.addImpliedTechnologies(technologies)

	result := make(map[string]TechInfo)
	for technology := range technologies {
		techInfo := TechInfo{
			Name:        technology,
			Description: "",
			Website:     "",
			Categories:  []string{},
			Groups:      []string{},
			Confidence:  100,
		}

		// Add tech details if available
		if app, ok := w.fingerprints.Apps[technology]; ok {
			techInfo.Description = app.Description
			techInfo.Website = app.Website
			techInfo.CPE = app.CPE
		}

		// Add category information
		if catIDs, ok := w.categoryMapping[technology]; ok {
			categoryNames := make([]string, 0, len(catIDs))
			groupIDsMap := make(map[int]struct{})

			for _, catID := range catIDs {
				if cat, ok := categoriesMapping[catID]; ok {
					categoryNames = append(categoryNames, cat.Name)

					// Collect groups for this category
					if groupIDs, ok := categoryToGroups[catID]; ok {
						for _, groupID := range groupIDs {
							groupIDsMap[groupID] = struct{}{}
						}
					}
				}
			}

			techInfo.Categories = categoryNames

			// Convert group IDs to names
			groupNames := make([]string, 0, len(groupIDsMap))
			for groupID := range groupIDsMap {
				if group, ok := groupsMapping[groupID]; ok {
					groupNames = append(groupNames, group.Name)
				}
			}
			techInfo.Groups = groupNames
		}

		result[technology] = techInfo
	}
	return result
}

// organizePatterns extracts patterns from compiled fingerprints and organizes them
// for efficient matching
func (w *Wappalyze) organizePatterns() error {
	for name, app := range w.fingerprints.Apps {
		// Organize header patterns
		if len(app.HeaderPatterns) > 0 {
			w.headerPatterns[name] = app.HeaderPatterns
		}

		// Organize cookie patterns
		if len(app.CookiePatterns) > 0 {
			w.cookiePatterns[name] = app.CookiePatterns
		}

		// Organize HTML patterns
		if len(app.HTMLPatterns) > 0 {
			w.htmlPatterns[name] = app.HTMLPatterns
		}

		// Organize script patterns
		if len(app.ScriptPatterns) > 0 {
			w.scriptPatterns[name] = app.ScriptPatterns
		}

		// Organize script src patterns
		if len(app.ScriptSrcPatterns) > 0 {
			w.scriptSrcPatterns[name] = app.ScriptSrcPatterns
		}

		// Organize meta patterns
		if len(app.MetaPatterns) > 0 {
			if _, ok := w.metaPatterns[name]; !ok {
				w.metaPatterns[name] = make(map[string][]*models.ParsedPattern)
			}

			for meta, patterns := range app.MetaPatterns {
				w.metaPatterns[name][meta] = patterns
			}
		}

		// Organize JS patterns
		if len(app.JSPatterns) > 0 {
			w.jsPatterns[name] = app.JSPatterns
		}
	}

	return nil
}

// buildImpliesMapping builds a mapping of technology to implied technologies
func (w *Wappalyze) buildImpliesMapping() {
	for name, app := range w.fingerprints.Apps {
		if len(app.ImpliedTechs) > 0 {
			w.impliesMapping[name] = app.ImpliedTechs
		}
	}
}

// buildCategoryMapping builds a mapping of technology to categories
func (w *Wappalyze) buildCategoryMapping() {
	for name, app := range w.fingerprints.Apps {
		if len(app.Cats) > 0 {
			w.categoryMapping[name] = app.Cats
		}
	}
}

// detectTechnologies performs the actual technology detection
func (w *Wappalyze) detectTechnologies(headers map[string][]string, body []byte, technologies map[string]struct{}) {
	// Match based on headers
	detection.MatchHeaders(w.headerPatterns, headers, technologies)

	// Extract cookies from headers and match
	cookies := detection.ExtractCookiesFromHeaders(headers)
	detection.MatchCookies(w.cookiePatterns, cookies, technologies)

	// Skip HTML-based detection if disabled
	if !w.config.DisableHTMLDetection {
		// Match based on HTML patterns
		detection.MatchHTML(w.htmlPatterns, body, technologies)
	}

	// Skip script detection if disabled
	if !w.config.DisableScriptDetection {
		// Match based on script patterns
		detection.MatchScripts(w.scriptPatterns, body, technologies)

		// Extract and match script sources
		scripts := parser.ExtractScripts(body)
		detection.MatchScriptSrc(w.scriptSrcPatterns, scripts, technologies)
	}

	// Skip meta tag detection if disabled
	if !w.config.DisableMetaDetection {
		// Extract and match meta tags
		metaTags := parser.ExtractMetaTags(body)
		detection.MatchMetaTags(w.metaPatterns, metaTags, technologies)
	}

	// Skip JS detection if disabled
	if !w.config.DisableJSDetection {
		// Extract and match JS patterns
		jsPatterns := parser.ExtractJS(body)
		detection.MatchJS(w.jsPatterns, jsPatterns, technologies)
	}
}

// addImpliedTechnologies adds technologies that are implied by detected ones
func (w *Wappalyze) addImpliedTechnologies(technologies map[string]struct{}) {
	var queue []string
	for tech := range technologies {
		queue = append(queue, tech)
	}

	for len(queue) > 0 {
		var current string
		current, queue = queue[0], queue[1:]

		if implies, ok := w.impliesMapping[current]; ok {
			for _, implied := range implies {
				if _, exists := technologies[implied]; !exists {
					technologies[implied] = struct{}{}
					queue = append(queue, implied)
				}
			}
		}
	}
}

// GetTechByGroup returns a list of technologies belonging to a specific group
func (w *Wappalyze) GetTechByGroup(groupID int) []string {
	var result []string

	// Get categories in this group
	categories := GetGroupCategories(groupID)
	if len(categories) == 0 {
		return result
	}

	// Create a map for faster lookup
	categoryMap := make(map[int]struct{})
	for _, catID := range categories {
		categoryMap[catID] = struct{}{}
	}

	// Find technologies with these categories
	for tech, catIDs := range w.categoryMapping {
		for _, catID := range catIDs {
			if _, ok := categoryMap[catID]; ok {
				result = append(result, tech)
				break // Found one matching category, no need to check others
			}
		}
	}

	return result
}

// AnalyzeURL fetches the given URL and performs technology detection
func (w *Wappalyze) AnalyzeURL(url string) (map[string]struct{}, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}

	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error fetching URL: %v", err)
	}
	defer resp.Body.Close()

	// Limit the body size if configured
	var reader io.Reader = resp.Body
	if w.config.MaxBodySize > 0 {
		reader = io.LimitReader(resp.Body, int64(w.config.MaxBodySize))
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	return w.Fingerprint(resp.Header, body), nil
}

// AnalyzeURLWithInfo fetches the given URL and performs technology detection with additional info
func (w *Wappalyze) AnalyzeURLWithInfo(url string) (map[string]models.AppInfo, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}

	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error fetching URL: %v", err)
	}
	defer resp.Body.Close()

	// Limit the body size if configured
	var reader io.Reader = resp.Body
	if w.config.MaxBodySize > 0 {
		reader = io.LimitReader(resp.Body, int64(w.config.MaxBodySize))
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	return w.FingerprintWithInfo(resp.Header, body), nil
}

// AnalyzeURLWithCats fetches the given URL and performs technology detection with category info
func (w *Wappalyze) AnalyzeURLWithCats(url string) (map[string]models.CatsInfo, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}

	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error fetching URL: %v", err)
	}
	defer resp.Body.Close()

	// Limit the body size if configured
	var reader io.Reader = resp.Body
	if w.config.MaxBodySize > 0 {
		reader = io.LimitReader(resp.Body, int64(w.config.MaxBodySize))
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	return w.FingerprintWithCats(resp.Header, body), nil
}

// AnalyzeURLWithTitle fetches the given URL and performs technology detection with page title
func (w *Wappalyze) AnalyzeURLWithTitle(url string) (map[string]struct{}, string, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}

	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		return nil, "", fmt.Errorf("error fetching URL: %v", err)
	}
	defer resp.Body.Close()

	// Limit the body size if configured
	var reader io.Reader = resp.Body
	if w.config.MaxBodySize > 0 {
		reader = io.LimitReader(resp.Body, int64(w.config.MaxBodySize))
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, "", fmt.Errorf("error reading response body: %v", err)
	}

	techs, title := w.FingerprintWithTitle(resp.Header, body)
	return techs, title, nil
}
