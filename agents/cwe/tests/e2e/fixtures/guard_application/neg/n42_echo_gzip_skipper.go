package main

import (
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func wire(e *echo.Echo) {
	e.Use(middleware.KeyAuth(validateKey))
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Skipper: func(c echo.Context) bool {
			return strings.HasPrefix(c.Request().Header.Get("Range"), "bytes")
		},
	}))
}
