package main

import jwtware "github.com/gofiber/contrib/jwt"

func setup(app *fiber.App) {
	app.Use(jwtware.New(jwtware.Config{
		SigningKey: jwtware.SigningKey{Key: []byte("s")},
		Filter: func(c *fiber.Ctx) bool {
			return c.Get("X-Internal") == "1"
		},
	}))
}
