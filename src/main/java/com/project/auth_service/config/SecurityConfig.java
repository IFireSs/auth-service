package com.project.auth_service.config;

import jakarta.servlet.DispatcherType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
public class SecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain logoutChain(HttpSecurity http,
                                           JwtOriginFilter jwtOriginFilter) throws Exception {
        http.securityMatcher(PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/api/v1/auth/logout/**"))
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                )
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                )
                .addFilterAfter(jwtOriginFilter, BearerTokenAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/logout/**").permitAll()
                        .anyRequest().denyAll()
                )
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain cookieAuthChain(HttpSecurity http) throws Exception {
        http.securityMatcher(cookieAuthMatcher())
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                )
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/login/**").permitAll()
                        .requestMatchers(HttpMethod.GET,  "/api/v1/auth/csrf/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/refresh/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/register/**").permitAll()
                        .anyRequest().denyAll()
                )
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    @Order(3)
    public SecurityFilterChain jwtAuthChain(HttpSecurity http,
                                            JwtOriginFilter jwtOriginFilter) throws Exception {
        http.securityMatcher("/api/v1/auth/**")
                .cors(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                )
                .addFilterAfter(jwtOriginFilter, BearerTokenAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .dispatcherTypeMatchers(DispatcherType.ERROR, DispatcherType.FORWARD).permitAll()
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated()
                );

        return http.build();
    }

    @Bean
    @Order(4)
    public SecurityFilterChain apiChain(HttpSecurity http,
                                        JwtOriginFilter jwtOriginFilter) throws Exception {
        http.cors(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                )
                .addFilterAfter(jwtOriginFilter, BearerTokenAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .dispatcherTypeMatchers(DispatcherType.ERROR, DispatcherType.FORWARD).permitAll()
                        .requestMatchers("/error").permitAll()
                        .requestMatchers(HttpMethod.GET, "/actuator/health", "/actuator/health/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/actuator/info").permitAll()
                        .requestMatchers(HttpMethod.GET, "/.well-known/jwks.json").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/admin/auth-clients/**").hasRole("SUPER_ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/api/v1/admin/auth-clients/**").hasRole("SUPER_ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/api/v1/admin/users/*/roles/admin").hasRole("SUPER_ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/v1/admin/users/*/roles/admin").hasRole("SUPER_ADMIN")
                        .requestMatchers("/api/v1/admin/**").hasAnyRole("ADMIN", "SUPER_ADMIN")
                        .requestMatchers("/swagger-ui/**", "/swagger-ui.html", "/v3/api-docs/**").permitAll()
                        .anyRequest().authenticated()
                );

        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter gac = new JwtGrantedAuthoritiesConverter();
        gac.setAuthoritiesClaimName("roles");
        gac.setAuthorityPrefix("ROLE_");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(gac);
        return converter;
    }

    private RequestMatcher cookieAuthMatcher() {
        return new OrRequestMatcher(
                PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/api/v1/auth/login/**"),
                PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/api/v1/auth/register/**"),
                PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET,  "/api/v1/auth/csrf/**"),
                PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/api/v1/auth/refresh/**")
        );
    }
}
