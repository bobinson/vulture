@Configuration
public class SecurityConfig {
    @Bean
    WebSecurityCustomizer customizer() {
        return web -> web.ignoring()
            .requestMatchers(new RequestHeaderRequestMatcher("X-Internal", "true"));
    }
}
