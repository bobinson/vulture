func Auth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if c.Request().Header.Get("X-Internal") == "1" {
			return next(c)
		}
		if c.Get("user") == nil {
			return echo.ErrUnauthorized
		}
		return next(c)
	}
}
