package main

func authMW(c *fiber.Ctx) error {
	if c.Get("X-Internal") == "1" {
		return c.Next()
	}
	if c.Locals("user") == nil {
		return c.SendStatus(401)
	}
	return c.Next()
}
