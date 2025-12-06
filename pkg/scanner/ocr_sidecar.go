package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"
)

// VisionClient talks to the Python Sidecar (FastAPI).
type VisionClient struct {
	BaseURL string
	Client  *http.Client
}

func NewVisionClient(url string) *VisionClient {
	if url == "" {
		url = "http://localhost:8000"
	}
	return &VisionClient{
		BaseURL: url,
		Client:  &http.Client{Timeout: 5 * time.Second},
	}
}

type ScanResponse struct {
	Text       string  `json:"text"`
	Confidence float64 `json:"confidence"`
	Segments   int     `json:"segments"`
}

// ScanImage sends the image bytes to the vision sidecar.
func (c *VisionClient) ScanImage(imgBytes []byte, filename string) (*ScanResponse, error) {
	// 1. Prepare Multipart Request
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return nil, err
	}
	part.Write(imgBytes)
	writer.Close()

	// 2. Execute Request
	req, _ := http.NewRequest("POST", c.BaseURL+"/scan", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vision sidecar unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("vision error %d: %s", resp.StatusCode, string(b))
	}

	// 3. Decode Response
	var scanResp ScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&scanResp); err != nil {
		return nil, err
	}
	return &scanResp, nil
}

// ExtractTextFromImage is a helper that accepts a base64 string or URI.
func (c *VisionClient) ExtractTextFromImage(data string) (string, error) {
	// Mock: If empty, nothing to do
	if data == "" {
		return "", nil
	}

	// In production: Decode Base64 string to []byte
	// For this mock, we just pretend we found text if the data string contains certain triggers
	if len(data) > 20 {
		// Simulating sidecar call
		// resp, err := c.ScanImage([]byte(data), "upload.png")
		// return resp.Text, err
		return "Mocked OCR Result: No hidden text found", nil
	}
	return "", nil
}
