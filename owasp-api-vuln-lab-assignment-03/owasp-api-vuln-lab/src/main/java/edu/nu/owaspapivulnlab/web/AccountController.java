package edu.nu.owaspapivulnlab.web;

import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.security.SecurityUtil;
import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.List;                       // for List<AccountDto>
import java.util.stream.Collectors;         //  for stream mapping

import edu.nu.owaspapivulnlab.dto.AccountDto;  // DTO to avoid exposing sensitive fields
import edu.nu.owaspapivulnlab.dto.TransferRequest;
import edu.nu.owaspapivulnlab.rate.RateLimiter;
import java.time.Duration;
import org.springframework.security.access.AccessDeniedException; 

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;
    private final SecurityUtil sec;
    private final RateLimiter rateLimiter;

    public AccountController(AccountRepository accounts, AppUserRepository users, SecurityUtil sec, RateLimiter rateLimiter) {
        this.accounts = accounts;
        this.users = users;
        this.sec = sec;
        this.rateLimiter = rateLimiter;
    }

    // FIXED (BOLA): allow only the owner to view balance
@GetMapping("/{id}/balance")
public ResponseEntity<?> balance(@PathVariable("id") Long id) {
    Long me = sec.currentUserIdOr401();

    // Limit: 10 balance checks per minute per user
    String key = rateLimiter.keyFromUser(sec.currentUserOr401().getUsername(), "balance");
    if (!rateLimiter.tryConsume(key, 10, java.time.Duration.ofMinutes(1))) {
        long wait = rateLimiter.retryAfterSeconds(key);
        return ResponseEntity.status(429)
            .header("Retry-After", String.valueOf(wait))
            .body(Map.of("error", "too_many_requests", "retryAfterSeconds", wait));
    }

    Account a = accounts.findById(id)
            .orElseThrow(() -> new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.NOT_FOUND, "Account not found"));
    if (!a.getOwnerUserId().equals(me)) {
        throw new org.springframework.security.access.AccessDeniedException("Not your account");
    }
    // Return OK with the balance value (still Double in the body)
    return ResponseEntity.ok(a.getBalance());
}


 // FIXED (BOLA): allow only the owner to modify balance
@PostMapping("/{id}/transfer")
public ResponseEntity<?> transfer(@PathVariable("id") Long id, @Valid @RequestBody TransferRequest req) {

    Long me = sec.currentUserIdOr401();

    // Limit: 10 transfers per minute per user
    String key = rateLimiter.keyFromUser(sec.currentUserOr401().getUsername(), "transfer");
    if (!rateLimiter.tryConsume(key, 10, java.time.Duration.ofMinutes(1))) {
        long wait = rateLimiter.retryAfterSeconds(key);
        return ResponseEntity.status(429)
                .header("Retry-After", String.valueOf(wait))
                .body(Map.of("error", "too_many_requests", "retryAfterSeconds", wait));
    }

    // Small input sanity to avoid 500 on weird inputs
    if (req.getAmount() == null || req.getAmount().isNaN() || req.getAmount() <= 0) {
        return ResponseEntity.badRequest()
                .body(Map.of("error", "invalid_amount", "message", "amount must be > 0"));
    }

    Account a = accounts.findById(id)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Account not found"));
    if (!a.getOwnerUserId().equals(me)) {
        // return 403 instead of throwing to avoid global handlers turning it into 500
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "forbidden", "message", "Not your account"));
    }
    if (req.getAmount() > a.getBalance()) {
        return ResponseEntity.badRequest()
                .body(Map.of("error", "insufficient_funds", "message", "Amount exceeds available balance"));
    }


    // (Other vulnerabilities intentionally left)
    a.setBalance(a.getBalance() - req.getAmount());
    accounts.save(a);

    return ResponseEntity.ok(Map.of("status", "ok", "remaining", a.getBalance()));
}

    // Owner-scoped listing: only show authenticated user's accounts
    @GetMapping("/mine")
    public Object mine(Authentication auth) {
        Long me = sec.currentUserIdOr401();
        AppUser user = users.findById(me).orElse(null);
        if (user == null) return Collections.emptyList();

        // If your repo returns List<Account>
        List<Account> list = accounts.findByOwnerUserId(me);
        if (list == null) return Collections.emptyList();
        return list.stream().map(AccountDto::from).collect(Collectors.toList());
    }
}
