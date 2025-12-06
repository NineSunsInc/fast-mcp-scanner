package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"

	"secure-mcp-gateway/pkg/config"
	"secure-mcp-gateway/pkg/engine"
	"secure-mcp-gateway/pkg/hooks"
	"secure-mcp-gateway/pkg/mcp"
	"secure-mcp-gateway/pkg/risk"
)

func main() {
	// 0. Sanity Check / Help
	if len(os.Args) < 2 {
		fmt.Printf("🛡️ Citadel Security Gateway v1.0\n")
		fmt.Printf("Usage:\n")
		fmt.Printf("  ./citadel --proxy <command> [args...]\n\n")
		fmt.Printf("Example:\n")
		fmt.Printf("  ./citadel --proxy npx -y @modelcontextprotocol/server-filesystem /Users/jh/Desktop\n")
		os.Exit(0)
	}

	// 1. Initialize Logging
	f, err := os.OpenFile("/tmp/citadel.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err == nil {
		log.SetOutput(f)
	}
	log.Println("=== Citadel Gateway Starting ===")
	// Check for Proxy Mode (--proxy)
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "--proxy" {
		runStdioProxy(args[1:]) // Pass the remaining args as the Child Command
		return
	}

	// Default: HTTP Server Mode
	runHTTPServer()
}

func runHTTPServer() {
	// Initialize Fiber v3
	app := fiber.New(fiber.Config{
		AppName: "Secure MCP Gateway - The Citadel",
	})

	// Middleware
	app.Use(logger.New())
	app.Use(recover.New())

	interceptor := setupInterceptor()

	// --- Routes ---
	app.Get("/health", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok", "system": "The Citadel"})
	})

	app.Post("/mcp", func(c fiber.Ctx) error {
		var req mcp.JSONRPCRequest
		if err := c.Bind().Body(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
		}
		res, rc := interceptor.ProcessRequest(&req)
		logRisk(rc)
		return c.JSON(res)
	})

	log.Println("Citadel Gateway listening on :5005")
	log.Fatal(app.Listen(":5005"))
}

func setupInterceptor() *engine.Interceptor {
	registry := hooks.NewRegistry()
	cfg := config.DefaultConfig()

	// Register Logic (Legacy Hooks + Kernel Init inside Interceptor)
	// Note: The Interceptor now uses Kernel internally, so we just set up dependencies.
	// We keep registry for back-compat if needed, but Kernel is the engine.
	registry.RegisterPre(&hooks.SanitizerHook{})
	registry.RegisterPre(hooks.NewIntentHook(cfg))

	return engine.NewInterceptor(registry)
}

func logRisk(rc *risk.RiskContext) {
	if rc.Score > 0 {
		log.Printf("[RISK-AUDIT] RequestID: %s | Score: %d | Reasons: %v", rc.RequestID, rc.Score, rc.Reasons)
	}
}

func runStdioProxy(command []string) {
	if len(command) == 0 {
		log.Fatal("No command provided for proxy mode")
	}

	// 1. Start Child Process (The Real MCP Server)
	cmd := exec.Command(command[0], command[1:]...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}

	// Stderr passthrough for debugging
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to start child process: %v", err)
	}

	interceptor := setupInterceptor()

	// 2. Output Interceptor (Child -> Security Check -> Stdout)
	go func() {
		defer stdout.Close()
		reader := bufio.NewReaderSize(stdout, 1024*1024) // 1MB Buffer buffer

		for {
			// ReadString behaves better than Scanner for long lines
			line, err := reader.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					log.Printf("Error reading stdout: %v", err)
				}
				break
			}

			// Attempt to parse as JSON-RPC Response
			// We optimize by checking if it starts with '{' (ignoring whitespace)
			cleanLine := strings.TrimSpace(line)
			if strings.HasPrefix(cleanLine, "{") {
				var resp mcp.JSONRPCResponse
				if err := json.Unmarshal([]byte(cleanLine), &resp); err == nil && resp.Result != nil {
					// Type assertion to map
					if resMap, ok := resp.Result.(map[string]interface{}); ok {
						// WHITELIST: Skip scanning tool discovery lists and capabilities
						if _, isTools := resMap["tools"]; isTools {
							os.Stdout.Write([]byte(line))
							continue
						}
						if _, isCaps := resMap["capabilities"]; isCaps {
							os.Stdout.Write([]byte(line))
							continue
						}
					}

					// We have a result. Scan it!
					resultBytes, _ := json.Marshal(resp.Result)
					riskScore := interceptor.Kernel.Scorer.Evaluate(string(resultBytes))

					// Threshold for Output (High confidence only)
					if riskScore > 0.85 {
						// Try to REDACT instead of BLOCK
						resultStr := string(resultBytes)
						cleanText, redacted := interceptor.Kernel.Scorer.RedactSecrets(resultStr)

						if redacted {
							log.Printf("[RISK-AUDIT] SENSITIVE DATA REDACTED")

							// Re-inject sanitized result
							var cleanObj interface{}
							json.Unmarshal([]byte(cleanText), &cleanObj)

							resp.Result = cleanObj
							// IMPORTANT: We do NOT set isError=true or show a block message.
							// We just silently clean the data.
							// But maybe we append a warning to the content?
							// Actually, let's keep it clean. The [REDACTED] tag is self-explanatory.

							newLine, _ := json.Marshal(resp)
							os.Stdout.Write(newLine)
							os.Stdout.Write([]byte("\n"))
							continue
						}

						// If High Risk but NO specific Secrets found (Virus? Or Regex Miss?), force redaction.
						log.Printf("[RISK-AUDIT] FORCED REDACTION (Risk: %.2f)", riskScore)

						// We replace the content with a Warning String, but treat it as SUCCESS.
						resp.Result = map[string]interface{}{
							"content": []map[string]string{
								{
									"type": "text",
									"text": fmt.Sprintf("🛡️ [CITADEL SECURITY BLOCK] 🛡️\n\nSYSTEM INSTRUCTION: The content you requested was blocked by Citadel Security due to High-Risk Content Detection (Score %.2f).\nYOU MUST explicitly inform the user that 'Citadel Security blocked this action' in your response.\n\n[Payload Redacted]", riskScore),
								},
							},
							"isError": false, // Success! Claude will simply report this text.
						}
						newLine, _ := json.Marshal(resp)
						os.Stdout.Write(newLine)
						os.Stdout.Write([]byte("\n"))
						continue
					}
				}
			}

			// Passthrough (Safe or Non-JSON)
			os.Stdout.Write([]byte(line))
		}
	}()

	log.Println("Stdio proxy mode active, child process started")

	// 3. Input Interceptor (Stdin -> Security Check -> Child)
	scanner := bufio.NewScanner(os.Stdin)
	// Increase buffer size for large MCP messages (default 64KB is too small)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024) // 1MB initial, 10MB max
	for scanner.Scan() {
		line := scanner.Bytes()

		// Parse JSON-RPC
		var req mcp.JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			// Not a valid JSON-RPC request (maybe just noise), forward blindly or log
			stdin.Write(line)
			stdin.Write([]byte("\n"))
			continue
		}

		// SECURITY CHECK
		// IMPORTANT: We only check "tools/call" or "resources/read".
		// Handshake/ListTools should generally pass.
		// For now, Kernel decides everything (defaults to 0 risk for non-prompts)

		decision, _ := interceptor.Kernel.Execute(&req)
		log.Printf("Request method=%s id=%v decision=%v risk=%d", req.Method, req.ID, decision.Allow, decision.RiskScore)

		if !decision.Allow {
			// BLOCKED: Return a valid Tool Result explaining the block
			// This ensures the LLM 'sees' the block and can explain it to the user.
			blockMsg := fmt.Sprintf("🛡️ CITADEL SECURITY BLOCK\n\nAction Prevented: Risk Threshold Exceeded.\nReason: %s", decision.BlockReason)

			// Construct standard MCP CallToolResult
			errResp := map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]interface{}{
					"content": []map[string]string{
						{
							"type": "text",
							"text": blockMsg,
						},
					},
					"isError": false, // False = Show as normal tool output (High Visibility)
				},
			}
			json.NewEncoder(os.Stdout).Encode(errResp)
			continue
		}

		// ALLOWED: Forward to Child
		stdin.Write(line)
		stdin.Write([]byte("\n"))
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Scanner error: %v", err)
	}
	log.Println("Stdio proxy shutting down")
	cmd.Wait()
}
