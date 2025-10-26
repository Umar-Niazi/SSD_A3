package edu.nu.owaspapivulnlab.dto;

import jakarta.validation.constraints.*;

public class TransferRequest {
    @NotNull
    @DecimalMin(value = "0.01", message = "amount must be > 0")
    @DecimalMax(value = "100000", message = "amount too large")
    private Double amount;

    public Double getAmount() { return amount; }
    public void setAmount(Double amount) { this.amount = amount; }
}
