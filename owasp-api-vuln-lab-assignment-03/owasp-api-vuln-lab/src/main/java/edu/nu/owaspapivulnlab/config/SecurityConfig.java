package edu.nu.owaspapivulnlab.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.*;

import java.io.IOException;
import java.util.Collections;

import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Configuration
public class SecurityConfig {

    // ✅ Added env-based and fallback secret sources
    @Value("${APP_JWT_SECRET:#{null}}") private String envSecret;
    @Value("${app.jwt.secret:#{null}}") private String propSecret;

    // ✅ Added issuer and audience for claim validation
    @Value("${app.jwt.issuer:owasp-api-vuln-lab}") private String jwtIssuer;
    @Value("${app.jwt.audience:owasp-api-vuln-lab-client}") private String jwtAudience;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    // VULNERABILITY(API7 Security Misconfiguration): overly permissive CORS/CSRF and antMatchers order
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable()); // APIs typically stateless; but add CSRF for state-changing in real apps
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.authorizeHttpRequests(reg -> reg
                .requestMatchers("/api/auth/**", "/h2-console/**").permitAll() // only these are public
                .requestMatchers("/api/admin/**").hasRole("ADMIN")             // admin-only endpoints
                .anyRequest().authenticated()                                  // everything else needs a token
        );

        http.headers(h -> h.frameOptions(f -> f.disable())); // allow H2 console

        // ✅ Load secret dynamically from env first, fallback to property
        String secret = (envSecret != null && !envSecret.isBlank()) ? envSecret : propSecret;
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException("JWT secret not configured (APP_JWT_SECRET).");
        }

        // Add improved JWT filter (issuer/audience validation)
        http.addFilterBefore(
                new JwtFilter(secret, jwtIssuer, jwtAudience),
                org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class
        );

        return http.build();
    }

    // Minimal JWT filter (VULNERABILITY FIXED: now validates audience, issuer, and enforces strict 401)
    static class JwtFilter extends OncePerRequestFilter {
        private final SecretKey key;
        private final String issuer;
        private final String audience;

        JwtFilter(String secret, String issuer, String audience) {
            SecretKey k;
            try {
                byte[] decoded = Decoders.BASE64.decode(secret);
                k = Keys.hmacShaKeyFor(decoded);
            } catch (Exception ex) {
                byte[] raw = secret.getBytes(StandardCharsets.UTF_8);
                k = Keys.hmacShaKeyFor(raw);
            }
            this.key = k;
            this.issuer = issuer;
            this.audience = audience;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            String auth = request.getHeader("Authorization");
            if (auth != null && auth.startsWith("Bearer ")) {
                String token = auth.substring(7);
                try {
                    JwtParserBuilder builder = Jwts.parserBuilder().setSigningKey(key);

                    // Enforce issuer and audience claims if configured
                    if (issuer != null && !issuer.isEmpty()) builder.requireIssuer(issuer);
                    if (audience != null && !audience.isEmpty()) builder.requireAudience(audience);

                    // parseClaimsJws automatically checks signature and expiry
                    Jws<Claims> parsed = builder.build().parseClaimsJws(token);
                    Claims c = parsed.getBody();

                    String user = c.getSubject();
                    String role = (String) c.get("role");

                    UsernamePasswordAuthenticationToken authn =
                            new UsernamePasswordAuthenticationToken(
                                    user, null,
                                    role != null
                                            ? Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role))
                                            : Collections.emptyList());

                    SecurityContextHolder.getContext().setAuthentication(authn);
                } catch (JwtException e) {
                    // FIX: do not silently continue; reject invalid or expired tokens
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"invalid_or_expired_token\"}");
                    return;
                }
            }
            chain.doFilter(request, response);
        }
    }
}
