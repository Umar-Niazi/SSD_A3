package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;              //  for mapping to DTOs

import edu.nu.owaspapivulnlab.dto.AppUserDto;  //   DTO

import edu.nu.owaspapivulnlab.dto.UserCreateRequest; // for mass assignment example
import org.springframework.security.crypto.password.PasswordEncoder; // for mass assignment example


@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;
    private final PasswordEncoder passwordEncoder;

    public UserController(AppUserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
    }

    // FIXED (Data Exposure): return DTO (no password/role/isAdmin)
    @GetMapping("/{id}")
    public AppUserDto get(@PathVariable("id") Long id) {
        AppUser u = users.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
        return AppUserDto.from(u);
    }

    // (Mass assignment still intentionally present for other rubric items)
    // FIXED (Data Exposure): return DTO instead of entity
    @PostMapping
    public AppUserDto create(@Valid @RequestBody UserCreateRequest req) {
        AppUser u = new AppUser();
        u.setUsername(req.getUsername());
        u.setEmail(req.getEmail());
        u.setPassword(passwordEncoder.encode(req.getPassword())); // hash password
        // enforce safe defaults (never from client)
        u.setRole("USER");
        u.setAdmin(false);

        AppUser saved = users.save(u);
        return AppUserDto.from(saved);
    }

    // FIXED (Data Exposure): map search results to DTOs
    @GetMapping("/search")
    public List<AppUserDto> search(@RequestParam String q) {
        return users.search(q).stream()
                .map(AppUserDto::from)
                .collect(Collectors.toList());
    }

    // FIXED (Data Exposure): list returns DTOs only
    @GetMapping
    public List<AppUserDto> list() {
        return users.findAll().stream()
                .map(AppUserDto::from)
                .collect(Collectors.toList());
    }

    // (Function-level still vuln, later task)
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable("id") Long id) {
        users.deleteById(id);
        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        return ResponseEntity.ok(response);
    }
}
