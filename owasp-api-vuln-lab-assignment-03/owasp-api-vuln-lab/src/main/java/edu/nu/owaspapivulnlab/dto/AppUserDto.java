package edu.nu.owaspapivulnlab.dto;

import edu.nu.owaspapivulnlab.model.AppUser;

public class AppUserDto {
    private Long id;
    private String username;
    private String email;

    public AppUserDto() {}
    public AppUserDto(Long id, String username, String email) {
        this.id = id; this.username = username; this.email = email;
    }

    public static AppUserDto from(AppUser u) {
        return new AppUserDto(u.getId(), u.getUsername(), u.getEmail());
    }

    public Long getId() { return id; }
    public String getUsername() { return username; }
    public String getEmail() { return email; }
}
