// validate checks all case JSON files against the agent-egress-bench spec.
// stdlib-only. No external dependencies.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Valid enum values for v1 schema.
var (
	validCategories = map[string]bool{
		"url": true, "request_body": true, "headers": true,
		"response_fetch": true, "response_mitm": true,
		"mcp_input": true, "mcp_tool": true, "mcp_chain": true,
	}

	validInputTypes = map[string]bool{
		"url": true, "request_body": true, "header": true,
		"response_content": true, "mcp_tool_call": true, "mcp_tool_result": true,
		"mcp_tool_definition": true, "mcp_tool_sequence": true,
	}

	validTransports = map[string]bool{
		"fetch_proxy": true, "http_proxy": true,
		"mcp_stdio": true, "mcp_http": true, "websocket": true,
	}

	validVerdicts = map[string]bool{
		"block": true, "allow": true,
	}

	validSeverities = map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true,
	}

	validFPRisk = map[string]bool{
		"low": true, "medium": true, "high": true,
	}

	validCapabilityTags = map[string]bool{
		"url_dlp": true, "request_body_dlp": true, "header_dlp": true,
		"response_injection": true, "mcp_input_scan": true, "mcp_tool_poison": true,
		"mcp_chain": true, "ssrf": true, "domain_blocklist": true,
		"entropy": true, "encoding_evasion": true, "benign": true,
	}

	validRequires = map[string]bool{
		"tls_interception": true, "request_body_scanning": true,
		"header_scanning": true, "response_scanning": true,
		"mcp_tool_baseline": true, "mcp_chain_memory": true,
	}
)

// Case represents a single benchmark case.
type Case struct {
	SchemaVersion  int                    `json:"schema_version"`
	ID             string                 `json:"id"`
	Category       string                 `json:"category"`
	Title          string                 `json:"title"`
	Description    string                 `json:"description"`
	InputType      string                 `json:"input_type"`
	Transport      string                 `json:"transport"`
	Payload        map[string]interface{} `json:"payload"`
	ExpectedVerdict string               `json:"expected_verdict"`
	Severity       string                 `json:"severity"`
	CapabilityTags []string               `json:"capability_tags"`
	Requires       []string               `json:"requires"`
	FPRisk         string                 `json:"false_positive_risk"`
	WhyExpected    string                 `json:"why_expected"`
	SafeExample    *bool                  `json:"safe_example,omitempty"`
	Notes          string                 `json:"notes"`
	Source         string                 `json:"source"`
}

func main() {
	casesDir := "cases"
	if len(os.Args) > 1 {
		casesDir = os.Args[1]
	}

	ids := make(map[string]string) // id -> file path
	var errors []string
	fileCount := 0

	err := filepath.Walk(casesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}

		fileCount++
		fileErrors := validateFile(path, ids)
		errors = append(errors, fileErrors...)
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error walking cases directory: %v\n", err)
		os.Exit(1)
	}

	if fileCount == 0 {
		fmt.Fprintf(os.Stderr, "no case files found in %s\n", casesDir)
		os.Exit(1)
	}

	if len(errors) > 0 {
		fmt.Fprintf(os.Stderr, "validation failed with %d error(s):\n\n", len(errors))
		for _, e := range errors {
			fmt.Fprintf(os.Stderr, "  %s\n", e)
		}
		os.Exit(1)
	}

	fmt.Printf("validated %d case files. all passed.\n", fileCount)
}

func validateFile(path string, ids map[string]string) []string {
	var errors []string
	addErr := func(msg string) {
		errors = append(errors, fmt.Sprintf("%s: %s", path, msg))
	}

	data, err := os.ReadFile(path)
	if err != nil {
		addErr(fmt.Sprintf("read error: %v", err))
		return errors
	}

	var c Case
	if err := json.Unmarshal(data, &c); err != nil {
		addErr(fmt.Sprintf("JSON parse error: %v", err))
		return errors
	}

	// Required fields
	if c.SchemaVersion != 1 {
		addErr(fmt.Sprintf("schema_version must be 1, got %d", c.SchemaVersion))
	}
	if c.ID == "" {
		addErr("missing id")
	}
	if c.Title == "" {
		addErr("missing title")
	}
	if c.Description == "" {
		addErr("missing description")
	}
	if c.WhyExpected == "" {
		addErr("missing why_expected")
	}
	if c.Payload == nil {
		addErr("missing payload")
	}

	// ID must match filename
	expectedFilename := c.ID + ".json"
	actualFilename := filepath.Base(path)
	if expectedFilename != actualFilename {
		addErr(fmt.Sprintf("id %q does not match filename %q", c.ID, actualFilename))
	}

	// Unique ID check
	if prev, exists := ids[c.ID]; exists {
		addErr(fmt.Sprintf("duplicate id %q (also in %s)", c.ID, prev))
	} else if c.ID != "" {
		ids[c.ID] = path
	}

	// Enum validation
	if !validCategories[c.Category] {
		addErr(fmt.Sprintf("invalid category: %q", c.Category))
	}
	if !validInputTypes[c.InputType] {
		addErr(fmt.Sprintf("invalid input_type: %q", c.InputType))
	}
	if !validTransports[c.Transport] {
		addErr(fmt.Sprintf("invalid transport: %q", c.Transport))
	}
	if !validVerdicts[c.ExpectedVerdict] {
		addErr(fmt.Sprintf("invalid expected_verdict: %q", c.ExpectedVerdict))
	}
	if !validSeverities[c.Severity] {
		addErr(fmt.Sprintf("invalid severity: %q", c.Severity))
	}
	if !validFPRisk[c.FPRisk] {
		addErr(fmt.Sprintf("invalid false_positive_risk: %q", c.FPRisk))
	}

	// Capability tags
	if len(c.CapabilityTags) == 0 {
		addErr("capability_tags must not be empty")
	}
	for _, tag := range c.CapabilityTags {
		if !validCapabilityTags[tag] {
			addErr(fmt.Sprintf("invalid capability_tag: %q", tag))
		}
	}

	// Requires
	for _, req := range c.Requires {
		if !validRequires[req] {
			addErr(fmt.Sprintf("invalid requires value: %q", req))
		}
	}

	// Category directory consistency
	expectedDir := categoryToDir(c.Category)
	actualDir := filepath.Base(filepath.Dir(path))
	if expectedDir != "" && expectedDir != actualDir {
		addErr(fmt.Sprintf("category %q expects directory %q, found in %q", c.Category, expectedDir, actualDir))
	}

	// Benign cases must have safe_example: true
	if c.ExpectedVerdict == "allow" && (c.SafeExample == nil || !*c.SafeExample) {
		addErr("benign cases (expected_verdict=allow) must have safe_example: true")
	}

	return errors
}

func categoryToDir(category string) string {
	switch category {
	case "url":
		return "url"
	case "request_body":
		return "request-body"
	case "headers":
		return "headers"
	case "response_fetch":
		return "response-fetch"
	case "response_mitm":
		return "response-mitm"
	case "mcp_input":
		return "mcp-input"
	case "mcp_tool":
		return "mcp-tool"
	case "mcp_chain":
		return "mcp-chain"
	default:
		return ""
	}
}
