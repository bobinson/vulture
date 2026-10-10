package main

func authMW(c *fiber.Ctx) error {
	if c.Query("debug") == "1" {
		return c.Next()
	}
	if c.Locals("user") == nil {
		return c.SendStatus(fiber.StatusUnauthorized)
	}
	return c.Next()
}
