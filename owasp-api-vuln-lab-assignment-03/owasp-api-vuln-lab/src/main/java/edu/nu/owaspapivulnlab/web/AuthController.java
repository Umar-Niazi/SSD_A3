package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.JwtService;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.crypto.password.PasswordEncoder;

import edu.nu.owaspapivulnlab.rate.RateLimiter;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AppUserRepository users;
    private final JwtService jwt;
    private final PasswordEncoder encoder;
    private final RateLimiter rateLimiter;

    public AuthController(AppUserRepository users, JwtService jwt, PasswordEncoder encoder, RateLimiter rateLimiter) {
        this.users = users;
        this.jwt = jwt;
        this.encoder = encoder;
        this.rateLimiter = rateLimiter;
    }

    // Login DTO with bean-style accessors so Jackson can deserialize reliably.
    public static class LoginReq {
        @NotBlank
        private String username;
        @NotBlank
        private String password;

        public LoginReq() {}

        public LoginReq(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String getUsername() { return username; }
        public String getPassword() { return password; }

        public void setUsername(String username) { this.username = username; }
        public void setPassword(String password) { this.password = password; }
    }

    public static class TokenRes {
        private String token;
        public TokenRes() {}
        public TokenRes(String token) { this.token = token; }
        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginReq req, HttpServletRequest http) {
        // Rate limit: 5 login attempts per minute per IP
        String key = rateLimiter.keyFromIp(http, "login");
        if (!rateLimiter.tryConsume(key, 5, Duration.ofMinutes(1))) {
            long wait = rateLimiter.retryAfterSeconds(key);
            return ResponseEntity.status(429)
                    .header("Retry-After", String.valueOf(wait))
                    .body(Map.of("error", "too_many_requests", "retryAfterSeconds", wait));
        }

        // Basic validation guard (will normally be enforced by @Valid, but double-check)
        if (req == null || req.getUsername() == null || req.getPassword() == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "username and password required"));
        }

        try {
            AppUser user = users.findByUsername(req.getUsername()).orElse(null);

            boolean ok = false;
            if (user != null && user.getPassword() != null) {
                try {
                    ok = encoder.matches(req.getPassword(), user.getPassword());
                } catch (Exception ignore) {
                    ok = false; // treat encoder issues as invalid credentials
                }
            }

            if (ok) {
                Map<String, Object> claims = new HashMap<>();
                claims.put("role", user.getRole());
                // kept for lab/demo purposes; consider restricting in production
                claims.put("isAdmin", user.isAdmin());
                String token = jwt.issue(user.getUsername(), claims);
                return ResponseEntity.ok(new TokenRes(token));
            }

            return ResponseEntity.status(401).body(Map.of("error", "invalid credentials"));
        } catch (Exception e) {
            // Keep client-facing message generic; log server-side if needed.
            return ResponseEntity.status(401).body(Map.of("error", "invalid credentials"));
        }
    }
}
