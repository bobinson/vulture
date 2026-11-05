package com.acme;

@Configuration
public class WebSecurity {
    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.csrf(c -> c.ignoringRequestMatchers(new RequestHeaderRequestMatcher("X-API-Client")))
            .authorizeHttpRequests(a -> a.requestMatchers("/", "/login").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }
}
