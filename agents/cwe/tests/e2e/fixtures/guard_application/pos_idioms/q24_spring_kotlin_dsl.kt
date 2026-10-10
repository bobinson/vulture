@Bean
fun filterChain(http: HttpSecurity): SecurityFilterChain {
    http {
        authorizeHttpRequests {
            authorize(RequestHeaderRequestMatcher("X-Internal"), permitAll)
            authorize(anyRequest, authenticated)
        }
    }
    return http.build()
}
