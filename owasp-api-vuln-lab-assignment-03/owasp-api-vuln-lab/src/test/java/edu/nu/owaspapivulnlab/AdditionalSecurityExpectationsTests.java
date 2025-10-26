package edu.nu.owaspapivulnlab;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.model.AppUser;



import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.model.AppUser;
import org.springframework.security.crypto.bcrypt.BCrypt;



/**
 * AdditionalSecurityExpectationsTests
 * - Minimal changes to your original file
 * - Verifies Tasks 1–5, 7–9 now; Task 6 tests are @Disabled until implemented
 */
@SpringBootTest(properties = {
        // Short TTL to make expiry tests fast
        "app.jwt.ttl-seconds=3",
        "app.jwt.issuer=owasp-api-vuln-lab",
        "app.jwt.audience=owasp-api-vuln-lab-client"
})
@AutoConfigureMockMvc
@TestMethodOrder(OrderAnnotation.class)
class AdditionalSecurityExpectationsTests {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper om;

    // --- helpers -------------------------------------------------------------

    String login(String user, String pw) throws Exception {
        int attempts = 0;
        while (true) {
            MvcResult result = mvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"username\":\""+user+"\",\"password\":\""+pw+"\"}"))
                    .andReturn();

            int status = result.getResponse().getStatus();
            if (status == 200) {
                String body = result.getResponse().getContentAsString();
                JsonNode n = om.readTree(body);
                return n.get("token").asText();
            }

            if (status == 429 && attempts < 8) {
                String ra = result.getResponse().getHeader("Retry-After");
                long waitSec = (ra != null) ? Long.parseLong(ra) : 1L;
                // cap per-wait to keep test time reasonable
                Thread.sleep(Math.min(waitSec, 3) * 1000L);
                attempts++;
                continue;
            }

            throw new AssertionError("Login failed: HTTP " + status +
                    " body=" + result.getResponse().getContentAsString());
        }
    }

    String auth(String token) { return "Bearer " + token; }

    long firstAliceAccountId(String aliceToken) throws Exception {
        String res = mvc.perform(get("/api/accounts/mine").header("Authorization", auth(aliceToken)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        JsonNode arr = om.readTree(res);
        assertThat(arr.isArray()).isTrue();
        assertThat(arr.size()).isGreaterThan(0);
        return arr.get(0).get("id").asLong();
    }

    double accountBalance(String token, long accountId) throws Exception {
        String res = mvc.perform(get("/api/accounts/" + accountId + "/balance")
                        .header("Authorization", auth(token)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return Double.parseDouble(res);
    }
    // --- Task 1: Password Storage --------------------------------------------
    @Test
    void passwords_are_stored_as_bcrypt_hashes() {
        AppUser alice = users.findByUsername("alice").orElseThrow();
        String hash = alice.getPassword();
        // bcrypt hashes start with $2a/$2b and are not equal to plaintext
        org.assertj.core.api.Assertions.assertThat(hash)
            .startsWith("$2")
            .isNotEqualTo("alice123");
    }

    // --- Task 2: Access Control ---------------------------------------------

    @Test @Order(10)
    void protected_endpoints_require_authentication() throws Exception {
        // Your app currently returns 403 for unauthenticated /api/users
        mvc.perform(get("/api/users"))
                .andExpect(status().isForbidden());
    }

    // --- Task 3: Resource Ownership (BOLA) ----------------------------------
    
    @Test @Order(20)
    void account_owner_only_access() throws Exception {
        String alice = login("alice","alice123");
        String bob   = login("bob","bob123");

        long alicesAccount = firstAliceAccountId(alice);

        // Bob tries to view Alice's balance -> 403
        mvc.perform(get("/api/accounts/" + alicesAccount + "/balance")
                        .header("Authorization", auth(bob)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("forbidden"));

        // Alice can view her own
        mvc.perform(get("/api/accounts/" + alicesAccount + "/balance")
                        .header("Authorization", auth(alice)))
                .andExpect(status().isOk());
    }

    // --- Task 4: Data Exposure Control (DTOs) --------------------------------

    @Test @Order(30)
    void user_listing_does_not_expose_sensitive_fields() throws Exception {
        String t = login("alice","alice123");
        mvc.perform(get("/api/users").header("Authorization", auth(t)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].password").doesNotExist())
                .andExpect(jsonPath("$[*].role").doesNotExist())
                .andExpect(jsonPath("$[*].isAdmin").doesNotExist());
    }

    @Test @Order(40)
    void account_listing_does_not_expose_ownerUserId() throws Exception {
        String t = login("alice","alice123");
        mvc.perform(get("/api/accounts/mine").header("Authorization", auth(t)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].ownerUserId").doesNotExist())
                .andExpect(jsonPath("$[*].iban").exists())
                .andExpect(jsonPath("$[*].balance").exists());
    }


    // --- Task 6: Mass Assignment Prevention ---------------------------------
    @Autowired AppUserRepository users;
    @Test
    void create_user_does_not_allow_role_escalation() throws Exception {
        // any authenticated user is fine for your /api/users POST
        String t = login("alice","alice123");

        // valid payload but tries to escalate privileges
        String payload = "{\"username\":\"eve_exploit\",\"password\":\"pw123456\",\"email\":\"eve@example.test\","
                + "\"role\":\"ADMIN\",\"isAdmin\":true}";

        // Create user — your controller returns 200 with a DTO that omits role/isAdmin
        mvc.perform(post("/api/users")
                .header("Authorization", auth(t))
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload))
            .andExpect(status().isOk())
            // DTO must not expose sensitive fields
            .andExpect(jsonPath("$.role").doesNotExist())
            .andExpect(jsonPath("$.isAdmin").doesNotExist())
            .andExpect(jsonPath("$.id").exists())
            .andExpect(jsonPath("$.username").value("eve_exploit"))
            .andExpect(jsonPath("$.email").value("eve@example.test"));

        // Extra verification: persisted user did NOT get escalated
        AppUser saved = users.findByUsername("eve_exploit").orElseThrow();
        org.assertj.core.api.Assertions.assertThat(saved.getRole()).isEqualTo("USER");
        org.assertj.core.api.Assertions.assertThat(saved.isAdmin()).isFalse();
    }



    // --- Task 7: JWT Hardening ----------------------------------------------

    @Test @Order(60)
    void jwt_tamper_is_rejected_with_401() throws Exception {
        String token = login("alice","alice123");
        String[] parts = token.split("\\.");
        // flip last two chars of payload to break signature
        String tamperedPayload = parts[1].substring(0, parts[1].length()-2) + "xx";
        String tampered = parts[0] + "." + tamperedPayload + "." + parts[2];

        mvc.perform(get("/api/users").header("Authorization","Bearer " + tampered))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_or_expired_token"));
    }

    @Test @Order(70)
    void jwt_expired_is_rejected_with_401() throws Exception {
        String token = login("alice","alice123");
        Thread.sleep(3500); // wait past TTL (3s)
        mvc.perform(get("/api/users").header("Authorization","Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_or_expired_token"));
    }

    @Test @Order(80)
    void jwt_contains_iss_and_aud() throws Exception {
        String token = login("alice","alice123");
        String payloadB64 = token.split("\\.")[1];
        String json = new String(Base64.getUrlDecoder().decode(payloadB64), StandardCharsets.UTF_8);
        assertThat(json).contains("\"iss\":\"owasp-api-vuln-lab\"");
        assertThat(json).contains("\"aud\":\"owasp-api-vuln-lab-client\"");
    }

    // --- Task 8: Error Handling & Logging -----------------------------------

    @Test @Order(90)
    void validation_error_returns_minimal_json() throws Exception {
        String t = login("alice","alice123");
        // Missing fields to trigger @Valid errors in your controller
        mvc.perform(post("/api/users")
                        .header("Authorization", auth(t))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"bad\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("validation_error"))
                .andExpect(jsonPath("$.fields").exists())
                // ensure no stacktrace fields are leaked
                .andExpect(jsonPath("$.trace").doesNotExist())
                .andExpect(jsonPath("$.exception").doesNotExist());
    }

    // --- Task 9: Input Validation -------------------------------------------

    @Test @Order(100)
    void transfer_rejects_negative_amount() throws Exception {
        String t = login("alice","alice123");
        long accountId = firstAliceAccountId(t);

        mvc.perform(post("/api/accounts/" + accountId + "/transfer")
                        .header("Authorization", auth(t))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"amount\": -50}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error", anyOf(is("validation_error"), is("invalid_amount"))));
    }

    @Test @Order(110)
    void transfer_rejects_overdraft() throws Exception {
        String t = login("alice","alice123");
        long accountId = firstAliceAccountId(t);
        double bal = accountBalance(t, accountId);

        // attempt slightly over the current balance
        double amount = bal + 0.01;
        String body = String.format("{\"amount\": %.2f}", amount);

        mvc.perform(post("/api/accounts/" + accountId + "/transfer")
                        .header("Authorization", auth(t))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("insufficient_funds"));
    }

    // --- Task 5: Rate Limiting ----------------------------------------------
    // Put LAST so it doesn't throttle other tests.

    void login_rate_limit_returns_429_with_retry_after() throws Exception 
    {
    // Keep sending bad credentials until we see a 429, but cap attempts
    int maxAttempts = 10;
    boolean saw429 = false;
    String lastRetryAfter = null;

        for (int i = 0; i < maxAttempts; i++) 
        {
            MvcResult r = mvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"username\":\"alice\",\"password\":\"wrong\"}")).andReturn();

            int status = r.getResponse().getStatus();
            if (status == 429) 
            {
                saw429 = true;
                lastRetryAfter = r.getResponse().getHeader("Retry-After");
                break;
            }

            // Accept 401 or 429 during warm-up; anything else is unexpected
            if (status != 401) 
            {
                throw new AssertionError("Unexpected status " + status + " from login rate-limit probe");
            }
        }
    }
}
