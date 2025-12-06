package main

import (
	"log"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"

	"secure-mcp-gateway/pkg/config"
	"secure-mcp-gateway/pkg/engine"
	"secure-mcp-gateway/pkg/hooks"
	"secure-mcp-gateway/pkg/mcp"
)

func main() {
	// Initialize Fiber v3
	app := fiber.New(fiber.Config{
		AppName: "Secure MCP Gateway - The Citadel",
	})

	// Middleware
	app.Use(logger.New())
	app.Use(recover.New())

	// --- Citadel Setup ---
	registry := hooks.NewRegistry()

	// Load Configuration (Smart/Composable)
	cfg := config.DefaultConfig()

	// Register Pre-Hooks
	registry.RegisterPre(&hooks.SanitizerHook{})
	registry.RegisterPre(hooks.NewIntentHook(cfg))
	registry.RegisterPre(&hooks.CDRHook{})

	// Register Post-Hooks
	registry.RegisterPost(hooks.NewTaintHook(cfg))
	registry.RegisterPost(hooks.NewIndirectInjectionHook(cfg))
	registry.RegisterPost(&hooks.EntropyHook{})

	interceptor := engine.NewInterceptor(registry)

	// --- Routes ---

	// Health Check
	app.Get("/health", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status": "ok",
			"system": "The Citadel",
		})
	})

	// MCP Endpoint
	app.Post("/mcp", func(c fiber.Ctx) error {
		var req mcp.JSONRPCRequest
		if err := c.Bind().Body(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
		}

		// Execute via Citadel
		res, rc := interceptor.ProcessRequest(&req)

		// Log Risk Score (In a real app, send to Splunk/Datadog)
		if rc.Score > 0 {
			log.Printf("[RISK-AUDIT] RequestID: %s | Score: %d | Level: %v | Reasons: %v", rc.RequestID, rc.Score, rc.Level(), rc.Reasons)
		}

		return c.JSON(res)
	})

	// Start Server
	log.Println("Citadel Gateway listening on :5005")
	log.Fatal(app.Listen(":5005"))
}
