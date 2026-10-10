package main

import "github.com/labstack/echo/v4/middleware"

func setup(e *echo.Echo) {
	e.Use(middleware.KeyAuthWithConfig(middleware.KeyAuthConfig{
		Skipper: func(c echo.Context) bool {
			return c.QueryParam("debug") == "1"
		},
		Validator: validateKey,
	}))
}
