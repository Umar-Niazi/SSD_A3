package edu.nu.owaspapivulnlab.security;

import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.Authentication;            // ✅ add this import
import org.springframework.web.server.ResponseStatusException;

@Component
public class SecurityUtil {
    private final AppUserRepository users;

    public SecurityUtil(AppUserRepository users) {
        this.users = users;
    }

    public AppUser currentUserOr401() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();  // ✅ no 'var'
        if (auth == null || !auth.isAuthenticated() || auth.getName() == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
        return users.findByUsername(auth.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));
    }

    public Long currentUserIdOr401() {
        return currentUserOr401().getId();
    }
}
