package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

@Service
public class JwtService {

    // Prefer environment variable; optional fallback to property (avoid in prod).
    @Value("${APP_JWT_SECRET:#{null}}")
    private String envSecret;

    @Value("${app.jwt.secret:#{null}}")
    private String propSecret;

    @Value("${app.jwt.ttl-seconds:900}") // default 15m
    private long ttlSeconds;

    @Value("${app.jwt.issuer}")
    private String issuer;

    @Value("${app.jwt.audience}")
    private String audience;

    private SecretKey signingKey() {
        String s = (envSecret != null && !envSecret.isBlank()) ? envSecret : propSecret;
        if (s == null || s.isBlank()) {
            throw new IllegalStateException("JWT secret not configured. Set APP_JWT_SECRET.");
        }
        try {
            byte[] b64 = Decoders.BASE64.decode(s);
            if (b64.length >= 32) return Keys.hmacShaKeyFor(b64);
        } catch (Exception ignore) { /* not base64 */ }
        byte[] raw = s.getBytes(StandardCharsets.UTF_8);
        if (raw.length < 32) {
            throw new IllegalStateException("JWT secret too short (<256-bit). Provide a longer secret.");
        }
        return Keys.hmacShaKeyFor(raw);
    }

    // Issue token with iss/aud and short TTL
    public String issue(String subject, Map<String, Object> claims) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .setSubject(subject)
                .setIssuer(issuer)
                .setAudience(audience)
                .addClaims(claims)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + ttlSeconds * 1000L))
                .signWith(signingKey(), SignatureAlgorithm.HS256)
                .compact();
    }
}
