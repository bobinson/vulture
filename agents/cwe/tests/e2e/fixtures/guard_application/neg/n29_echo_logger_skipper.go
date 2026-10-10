package main

import (
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	e := echo.New()
	e.Use(echojwt.JWT([]byte("k")))
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Skipper: func(c echo.Context) bool {
			return c.Request().Header.Get("User-Agent") == "kube-probe/1.27"
		},
	}))
	e.Logger.Fatal(e.Start(":8080"))
}
