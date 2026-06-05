# Интеграция Resource Server

## Runtime-конфигурация

Resource-сервис должен знать issuer auth-service, JWKS endpoint и ожидаемую audience:

```env
AUTH_SERVICE_ISSUER=auth-service
AUTH_SERVICE_JWKS_URI=http://auth-service:8080/.well-known/jwks.json
AUTH_SERVICE_AUDIENCE=budget-service
```

Private key остаётся только в auth-service. Resource-сервис получает public key через JWKS и не может сам выпускать валидные access tokens.

Значение `AUTH_SERVICE_AUDIENCE` должно совпадать с `tokenAudience` auth-client'а, через который пользователь получает access token. Это отделяет токены для разных resource-сервисов: валидный по подписи токен для одного audience не должен приниматься другим resource-сервисом.

## Настройка Spring Security

Самый простой вариант для Spring Boot resource server:

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: ${AUTH_SERVICE_JWKS_URI}

auth-service:
  issuer: ${AUTH_SERVICE_ISSUER}
  jwks-uri: ${AUTH_SERVICE_JWKS_URI}
  audience: ${AUTH_SERVICE_AUDIENCE}
```

Issuer и audience нужно проверять явно через `JwtDecoder`:

```java
@Bean
JwtDecoder jwtDecoder(
        @Value("${auth-service.jwks-uri}") String jwksUri,
        @Value("${auth-service.issuer}") String issuer,
        @Value("${auth-service.audience}") String audience
) {
    NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwksUri).build();

    OAuth2TokenValidator<Jwt> issuerValidator = JwtValidators.createDefaultWithIssuer(issuer);
    OAuth2TokenValidator<Jwt> audienceValidator = jwt -> {
        if (jwt.getAudience().contains(audience)) {
            return OAuth2TokenValidatorResult.success();
        }

        OAuth2Error error = new OAuth2Error(
                OAuth2ErrorCodes.INVALID_TOKEN,
                "Required audience is missing",
                null
        );
        return OAuth2TokenValidatorResult.failure(error);
    };

    decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
            issuerValidator,
            audienceValidator
    ));
    return decoder;
}
```

Claim `roles` из auth-service нужно мапить в Spring authorities:

```java
@Bean
JwtAuthenticationConverter jwtAuthenticationConverter() {
    JwtGrantedAuthoritiesConverter roles = new JwtGrantedAuthoritiesConverter();
    roles.setAuthoritiesClaimName("roles");
    roles.setAuthorityPrefix("ROLE_");

    JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
    converter.setJwtGrantedAuthoritiesConverter(roles);
    return converter;
}
```

И подключить converter в resource server config:

```java
.oauth2ResourceServer(oauth2 -> oauth2
        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
)
```

## Получение текущего пользователя

В качестве стабильного внешнего user id нужно использовать `uid`:

```java
@GetMapping("/api/v1/budgets")
List<BudgetResponse> budgets(@AuthenticationPrincipal Jwt jwt) {
    Long userId = ((Number) jwt.getClaim("uid")).longValue();
    return budgetService.findByUserId(userId);
}
```

Роли нужно проверять через Spring Security:

```java
@PreAuthorize("hasRole('USER')")
```

`sid` не используется как user id. `sid` идентифицирует login-сессию в auth-service, а не пользователя.

## Граница Stateful и Stateless

Auth-service может работать с таким режимом:

```env
APP_SECURITY_ACCESS_TOKEN_VALIDATION_MODE=stateful
```

В этом режиме auth-service проверяет активность auth-client'а и свою таблицу refresh-сессий по `uid + client_id + sid`, поэтому logout может сразу закрывать доступ к защищённым endpoint'ам auth-service.

Resource-сервисы не должны использовать эту stateful-проверку. Они должны валидировать access token stateless:

- проверять подпись через JWKS;
- проверять issuer;
- проверять audience;
- проверять expiration;
- читать `uid`, `roles` и при необходимости `client_id`.

Так resource-сервисы остаются независимыми от persistence-слоя auth-service. Logout сразу отзывает refresh/session state в auth-service, а уже выпущенные access tokens остаются валидными в resource-сервисах до короткого срока истечения.
