package edu.nu.owaspapivulnlab.dto;

import edu.nu.owaspapivulnlab.model.Account;

public class AccountDto {
    private Long id;
    private String iban;
    private Double balance;

    public AccountDto() {}
    public AccountDto(Long id, String iban, Double balance) {
        this.id = id; this.iban = iban; this.balance = balance;
    }

    public static AccountDto from(Account a) {
        return new AccountDto(a.getId(), a.getIban(), a.getBalance());
    }

    public Long getId() { return id; }
    public String getIban() { return iban; }
    public Double getBalance() { return balance; }
}
