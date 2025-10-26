package edu.nu.owaspapivulnlab.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DataSeeder {

    @Bean
    CommandLineRunner seed(AppUserRepository users, AccountRepository accounts, PasswordEncoder encoder) {
        return args -> {
            if (users.count() == 0) {
                AppUser u1 = users.save(
                        AppUser.builder()
                                .username("alice")
                                .password(encoder.encode("alice123"))
                                .email("alice@cydea.tech")
                                .role("USER")
                                .isAdmin(false)
                                .build()
                );

                AppUser u2 = users.save(
                        AppUser.builder()
                                .username("bob")
                                .password(encoder.encode("bob123"))
                                .email("bob@cydea.tech")
                                .role("ADMIN")
                                .isAdmin(true)
                                .build()
                );

                accounts.save(
                    Account.builder()
                        .ownerUserId(u1.getId())
                        .iban("GB33BUKB20201555555555")   // valid-format test IBAN
                        .balance(1000.0)
                        .build()
                );

                accounts.save(
                    Account.builder()
                        .ownerUserId(u2.getId())
                        .iban("DE89370400440532013000")  // valid-format test IBAN
                        .balance(5000.0)
                        .build()
                );

            }
        };
    }
}
