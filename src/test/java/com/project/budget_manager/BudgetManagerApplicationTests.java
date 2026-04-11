package com.project.budget_manager;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.project.budget_manager.security.api.dto.RegisterRequest;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class BudgetManagerApplicationTests {
    private static final String USER_AGENT = "JUnit";
    private static final String REFRESH_ATTEMPT_HEADER = "X-Refresh-Attempt-Id";
    private static final String TEST_JWT_SECRET = "test-secret-0123456789-test-secret";
    private static final String TEST_SCHEMA = "auth_test_" + UUID.randomUUID().toString().replace("-", "");

    @DynamicPropertySource
    static void registerSecurityProperties(DynamicPropertyRegistry registry) {
        registry.add("app.security.jwt.secret", () -> TEST_JWT_SECRET);
        registry.add("spring.jpa.properties.hibernate.default_schema", () -> TEST_SCHEMA);
        registry.add("spring.flyway.default-schema", () -> TEST_SCHEMA);
        registry.add("spring.flyway.schemas", () -> TEST_SCHEMA);
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void registerReturnsConflictForDuplicateUser() throws Exception {
        CsrfContext csrf = getCsrfContext();

        String username = "test_" + UUID.randomUUID().toString().replace("-", "");
        String payload = objectMapper.writeValueAsString(new RegisterRequest(
                username,
                "Password123!",
                username + "@example.com"
        ));

        mockMvc.perform(post("/api/v1/auth/register")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/v1/auth/register")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isConflict())
                .andExpect(content().string("conflict"))
                .andExpect(result -> org.junit.jupiter.api.Assertions.assertTrue(
                        result.getResponse().getHeaders(HttpHeaders.SET_COOKIE).isEmpty()
                ));
    }

    @Test
    void refreshIsIdempotentForSameAttemptIdOnly() throws Exception {
        CsrfContext csrf = getCsrfContext();
        String username = "refresh_" + UUID.randomUUID().toString().replace("-", "");
        String registerPayload = objectMapper.writeValueAsString(new RegisterRequest(
                username,
                "Password123!",
                username + "@example.com"
        ));

        MvcResult registerResult = mockMvc.perform(post("/api/v1/auth/register")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerPayload))
                .andExpect(status().isOk())
                .andReturn();

        Cookie originalRefreshCookie = registerResult.getResponse().getCookie("refresh_token");
        Cookie sessionCookie = registerResult.getResponse().getCookie("session_id");
        String attemptId = UUID.randomUUID().toString();

        MvcResult firstRefresh = mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(csrf.cookie(), originalRefreshCookie, sessionCookie)
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .header(REFRESH_ATTEMPT_HEADER, attemptId))
                .andExpect(status().isOk())
                .andReturn();

        Cookie firstReplayCookie = firstRefresh.getResponse().getCookie("refresh_token");

        MvcResult replaySameAttempt = mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(csrf.cookie(), originalRefreshCookie, sessionCookie)
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .header(REFRESH_ATTEMPT_HEADER, attemptId))
                .andExpect(status().isOk())
                .andReturn();

        Cookie replaySameAttemptCookie = replaySameAttempt.getResponse().getCookie("refresh_token");

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(csrf.cookie(), originalRefreshCookie, sessionCookie)
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .header(REFRESH_ATTEMPT_HEADER, UUID.randomUUID().toString()))
                .andExpect(status().isConflict())
                .andExpect(content().string("Refresh already processed by another request"));

        org.junit.jupiter.api.Assertions.assertNotNull(firstReplayCookie);
        org.junit.jupiter.api.Assertions.assertNotNull(replaySameAttemptCookie);
        org.junit.jupiter.api.Assertions.assertEquals(firstReplayCookie.getValue(), replaySameAttemptCookie.getValue());
    }

    @Test
    void logoutAllInvalidatesIssuedAccessTokenInStatefulMode() throws Exception {
        CsrfContext csrf = getCsrfContext();
        String username = "logout_all_" + UUID.randomUUID().toString().replace("-", "");
        String registerPayload = objectMapper.writeValueAsString(new RegisterRequest(
                username,
                "Password123!",
                username + "@example.com"
        ));

        MvcResult registerResult = mockMvc.perform(post("/api/v1/auth/register")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerPayload))
                .andExpect(status().isOk())
                .andReturn();

        String accessToken = readAccessToken(registerResult);

        mockMvc.perform(get("/api/v1/auth/sessions")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/v1/auth/logout-all")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/v1/auth/sessions")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refreshWithoutSessionIdReturnsUnauthorizedButKeepsSessionAlive() throws Exception {
        CsrfContext csrf = getCsrfContext();
        MvcResult registerResult = registerUser(csrf, "missing_sid_" + UUID.randomUUID().toString().replace("-", ""));

        Cookie refreshCookie = registerResult.getResponse().getCookie("refresh_token");
        Cookie sessionCookie = registerResult.getResponse().getCookie("session_id");
        String accessToken = readAccessToken(registerResult);

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(csrf.cookie(), refreshCookie)
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Invalid refresh token"));

        mockMvc.perform(get("/api/v1/auth/sessions")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(csrf.cookie(), refreshCookie, sessionCookie)
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT))
                .andExpect(status().isOk());
    }

    @Test
    void refreshWithDifferentUserAgentRevokesSession() throws Exception {
        CsrfContext csrf = getCsrfContext();
        MvcResult registerResult = registerUser(csrf, "ua_mismatch_" + UUID.randomUUID().toString().replace("-", ""));

        Cookie refreshCookie = registerResult.getResponse().getCookie("refresh_token");
        Cookie sessionCookie = registerResult.getResponse().getCookie("session_id");
        String accessToken = readAccessToken(registerResult);

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(csrf.cookie(), refreshCookie, sessionCookie)
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, "Other-Agent")
                        .with(remoteAddr("10.0.0.5")))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Refresh token reuse detected"));

        mockMvc.perform(get("/api/v1/auth/sessions")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(csrf.cookie(), refreshCookie, sessionCookie)
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void logoutWithBearerOnlyRevokesCurrentSession() throws Exception {
        CsrfContext csrf = getCsrfContext();
        MvcResult registerResult = registerUser(csrf, "logout_bearer_" + UUID.randomUUID().toString().replace("-", ""));
        String accessToken = readAccessToken(registerResult);

        mockMvc.perform(post("/api/v1/auth/logout")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/v1/auth/sessions")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void accessTokenWithWrongIssuerIsRejected() throws Exception {
        CsrfContext csrf = getCsrfContext();
        MvcResult registerResult = registerUser(csrf, "wrong_issuer_" + UUID.randomUUID().toString().replace("-", ""));
        JsonNode validBody = objectMapper.readTree(registerResult.getResponse().getContentAsString());
        String validAccessToken = validBody.get("accessToken").asText();
        String wrongIssuerToken = issueAccessTokenWithWrongIssuer(validAccessToken, "other-issuer");

        mockMvc.perform(get("/api/v1/auth/sessions")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + wrongIssuerToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void badLoginDoesNotClearExistingCookies() throws Exception {
        CsrfContext csrf = getCsrfContext();
        MvcResult registerResult = registerUser(csrf, "bad_login_" + UUID.randomUUID().toString().replace("-", ""));
        Cookie refreshCookie = registerResult.getResponse().getCookie("refresh_token");
        Cookie sessionCookie = registerResult.getResponse().getCookie("session_id");

        String payload = """
                {
                  "username": "nobody",
                  "password": "wrong"
                }
                """;

        mockMvc.perform(post("/api/v1/auth/login")
                        .cookie(csrf.cookie(), refreshCookie, sessionCookie)
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Invalid credentials"))
                .andExpect(result -> org.junit.jupiter.api.Assertions.assertTrue(
                        result.getResponse().getHeaders(HttpHeaders.SET_COOKIE).isEmpty()
                ));
    }

    private CsrfContext getCsrfContext() throws Exception {
        MvcResult csrfResult = mockMvc.perform(get("/api/v1/auth/csrf"))
                .andExpect(status().isOk())
                .andReturn();

        Cookie xsrfCookie = csrfResult.getResponse().getCookie("XSRF-TOKEN");
        JsonNode csrfBody = objectMapper.readTree(csrfResult.getResponse().getContentAsString());
        return new CsrfContext(xsrfCookie, csrfBody.get("token").asText());
    }

    private String readAccessToken(MvcResult result) throws Exception {
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        return body.get("accessToken").asText();
    }

    private MvcResult registerUser(CsrfContext csrf, String username) throws Exception {
        String payload = objectMapper.writeValueAsString(new RegisterRequest(
                username,
                "Password123!",
                username + "@example.com"
        ));

        return mockMvc.perform(post("/api/v1/auth/register")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isOk())
                .andReturn();
    }

    private RequestPostProcessor remoteAddr(String ip) {
        return request -> {
            request.setRemoteAddr(ip);
            return request;
        };
    }

    private String issueAccessTokenWithWrongIssuer(String validAccessToken, String issuer) throws Exception {
        JsonNode tokenPayload = objectMapper.readTree(new String(
                java.util.Base64.getUrlDecoder().decode(validAccessToken.split("\\.")[1]),
                StandardCharsets.UTF_8
        ));

        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(600))
                .subject(tokenPayload.get("sub").asText())
                .claim("uid", tokenPayload.get("uid").asLong())
                .claim("roles", List.of("USER"))
                .claim("sid", tokenPayload.get("sid").asText())
                .build();

        SecretKey secretKey = new SecretKeySpec(TEST_JWT_SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        JwtEncoder encoder = new org.springframework.security.oauth2.jwt.NimbusJwtEncoder(new ImmutableSecret<>(secretKey));
        return encoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(MacAlgorithm.HS256).build(),
                claims
        )).getTokenValue();
    }

    private record CsrfContext(Cookie cookie, String token) {
    }
}
