package main

import "github.com/gin-gonic/gin"

func Flags() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("X-Flags-Off") == "1" {
			c.Next()
			return
		}
		if isAuthenticated(c) {
			c.Set("flags", loadFlags(c))
		}
		c.Next()
	}
}
