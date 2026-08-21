func Register(router *gin.Engine) {
	router.GET("/actuator/env", RequireAuth(), DumpEnvironment)
}
