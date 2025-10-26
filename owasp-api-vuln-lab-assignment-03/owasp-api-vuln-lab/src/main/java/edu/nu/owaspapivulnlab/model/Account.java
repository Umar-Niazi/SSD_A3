package edu.nu.owaspapivulnlab.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;

import lombok.*;

@Entity @Data @NoArgsConstructor @AllArgsConstructor @Builder
public class Account {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private Long ownerUserId;

    @Pattern(regexp = "[A-Z0-9]{15,34}", message = "invalid IBAN format")
    private String iban;

    @Min(value = 0, message = "balance must be non-negative")
    @Max(value = 1000000, message = "balance too large")
    private Double balance;
}
