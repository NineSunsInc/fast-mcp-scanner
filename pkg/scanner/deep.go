package scanner

import (
	"encoding/base64"
	"strings"
)

// ScanResult holds the findings of a deep scan.
type ScanResult struct {
	IsSafe      bool
	RiskScore   int
	Findings    []string
	ContentType string
}

type DeepScanner struct {
	// In a real system, we'd have bindings to ClamAV, Tesseract, libmagic, etc.
}

func NewDeepScanner() *DeepScanner {
	return &DeepScanner{}
}

// ScanBase64 attempts to identify threats in raw data.
func (s *DeepScanner) ScanBase64(data string) *ScanResult {
	result := &ScanResult{IsSafe: true, Findings: []string{}}

	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		result.RiskScore += 10
		result.Findings = append(result.Findings, "Invalid Base64 encoding")
		return result
	}

	// 1. Magic Number Analysis (Polyglot Detection)
	// Check if it scans as multiple file types (e.g. GIF + Script)
	if isPolyglot(raw) {
		result.IsSafe = false
		result.RiskScore += 100
		result.Findings = append(result.Findings, "CRITICAL: Polyglot File Detected (GIF+HTML)")
		return result
	}

	// 2. Metadata Extraction (EXIF/XMP)
	// Attackers hide prompts in EXIF 'Comment' fields.
	if containsHiddenMetadata(raw) {
		result.RiskScore += 40
		result.Findings = append(result.Findings, "Suspicious Metadata detected")
	}

	// 3. Binary/Shellcode Analysis
	// Check for common shell paths or high density of control characters (NOP sleds)
	if isShellcode(raw) {
		result.RiskScore += 100
		result.Findings = append(result.Findings, "CRITICAL: Potential Binary Shellcode Detected")
		result.IsSafe = false
	}

	return result
}

func isShellcode(data []byte) bool {
	s := string(data)
	// Signature 1: Common paths
	if strings.Contains(s, "/bin/sh") || strings.Contains(s, "/bin/bash") || strings.Contains(s, "cmd.exe") {
		return true
	}
	// Signature 2: NOP Sleds (0x90 repeated) or suspicious hex patterns
	// Simple heuristic: If > 30% of bytes are non-printable but not obviously image/audio data
	nonPrintable := 0
	for _, b := range data {
		if b < 32 || b > 126 {
			nonPrintable++
		}
	}
	// If mostly binary and contains "exec" or "system", flag it
	// (Check logic simplified for demo speed)
	if nonPrintable > len(data)/3 && (strings.Contains(s, "exec") || strings.Contains(s, "system")) {
		return true
	}
	return false
}

// isPolyglot simulates detection of "GIFAR" (GIF + JAR) or similar attacks.
func isPolyglot(data []byte) bool {
	// Mock: If data starts with GIF89a but contains "<script>", it's a polyglot
	s := string(data)
	if strings.HasPrefix(s, "GIF89a") && strings.Contains(s, "<script>") {
		return true
	}
	return false
}

// containsHiddenMetadata simulates checking for injected prompts in EXIF.
func containsHiddenMetadata(data []byte) bool {
	// Mock: Check for common injection strings in binary data
	s := string(data)
	if strings.Contains(strings.ToLower(s), "ignore previous") {
		return true // Attack in metadata!
	}
	return false
}
