package main

import (
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
)

func wire(e *echo.Echo, key []byte) {
	e.Use(echojwt.WithConfig(echojwt.Config{
		SigningKey: key,
		Skipper: func(c echo.Context) bool {
			return c.Path() == "/healthz"
		},
	}))
}
