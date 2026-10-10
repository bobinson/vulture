package main

import "github.com/gofiber/fiber/v2/middleware/keyauth"

func setup(app *fiber.App) {
	app.Use(keyauth.New(keyauth.Config{
		Next: func(c *fiber.Ctx) bool {
			return c.Get("X-Internal") == "1"
		},
		Validator: validate,
	}))
}
