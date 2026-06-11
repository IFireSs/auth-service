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

Access token также содержит отдельную audience самого auth-service. Поэтому resource-сервис
должен проверять, что `aud` содержит его `AUTH_SERVICE_AUDIENCE`, а не требовать точного
равенства всего списка audience.

## Настройка Spring Security

Resource-сервису нужны зависимости:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

Для Spring Boot 3.5 рекомендуется полностью доверить создание `JwtDecoder` и mapping ролей auto-configuration:

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: ${AUTH_SERVICE_ISSUER}
          jwk-set-uri: ${AUTH_SERVICE_JWKS_URI}
          audiences:
            - ${AUTH_SERVICE_AUDIENCE}
          jws-algorithms:
            - RS256
          authorities-claim-name: roles
          authority-prefix: ROLE_
```

Здесь свойства выполняют разные задачи:

- `issuer-uri` валидирует claim `iss`. Значение должно точно совпадать с issuer auth-service.
- `jwk-set-uri` указывает, откуда получать public keys. Auth-service не предоставляет OIDC discovery metadata,
  поэтому это свойство обязательно.
- `audiences` валидирует, что claim `aud` содержит audience конкретного resource-сервиса.
- `jws-algorithms` ограничивает принимаемый алгоритм значением `RS256`.
- `authorities-claim-name` читает authorities из claim `roles`.
- `authority-prefix` преобразует роль `USER` в authority `ROLE_USER`.

При одновременном указании `issuer-uri` и `jwk-set-uri` Spring Security не пытается получить discovery metadata
по issuer, но продолжает проверять claim `iss`.

Не нужно одновременно объявлять эти свойства и создавать собственный `JwtDecoder`: пользовательский bean заменит
Boot auto-configuration и сделает часть настроек неочевидной или неиспользуемой.

## Полная конфигурация SecurityFilterChain

```java
package com.example.budget.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.GET, "/actuator/health/**").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        return http.build();
    }
}
```

Mapping ролей уже настроен свойствами `authorities-claim-name` и `authority-prefix`, поэтому отдельный
`JwtAuthenticationConverter` не требуется. После mapping роль `USER` становится authority `ROLE_USER`, и работают
проверки `hasRole("USER")` и `@PreAuthorize("hasRole('USER')")`.

`@EnableMethodSecurity` нужен только если сервис использует `@PreAuthorize`, `@PostAuthorize` и другие method-level
проверки. Правила в `authorizeHttpRequests` работают без него.

## Когда нужен собственный JwtDecoder

Собственный bean `JwtDecoder` нужен только для нестандартных проверок, которых нет в Boot properties. Например,
если требуется обязательная валидация дополнительных custom claims.

Показанная declarative-конфигурация проверяет подпись, `iss`, `aud`, время жизни и мапит `roles`, но сама по себе не
отклоняет токен из-за отсутствующего или неверно типизированного `uid`, `sid` либо `client_id`. Если resource-сервис
использует эти claims как security boundary или хочет строго применять весь `docs/jwt-contract.md`, ему нужен custom
validator и, следовательно, собственный `JwtDecoder`.

При ручной конфигурации нужно сохранить стандартные проверки времени жизни и issuer через
`JwtValidators.createDefaultWithIssuer(...)`, явно добавить audience validator и затем custom validator через
`DelegatingOAuth2TokenValidator`. Объявление собственного `JwtDecoder` полностью заменяет Boot auto-configuration.

## Получение текущего пользователя

В качестве стабильного внешнего user id нужно использовать `uid`:

```java
@GetMapping("/api/v1/budgets")
List<BudgetResponse> budgets(@AuthenticationPrincipal Jwt jwt) {
    UUID userId = UUID.fromString(jwt.getClaimAsString("uid"));
    return budgetService.findByUserId(userId);
}
```

Claim `uid` передается строкой в формате UUID. Не следует парсить его как `Long` или использовать `sub`/`sid` вместо него.

Роли нужно проверять через Spring Security:

```java
@PreAuthorize("hasRole('USER')")
List<BudgetResponse> budgets(...) {
    // ...
}
```

`sid` не используется как user id. `sid` идентифицирует login-сессию в auth-service, а не пользователя.

## Граница Stateful и Stateless

Auth-service может работать с таким режимом:

```env
APP_SECURITY_ACCESS_TOKEN_VALIDATION_MODE=stateful
```

Auth-service проверяет активный бан при login, refresh и при валидации каждого bearer JWT для собственных endpoint'ов.
В stateful-режиме он дополнительно проверяет активность auth-client'а и свою таблицу refresh-сессий
по `uid + client_id + sid`, поэтому logout или бан могут сразу закрывать доступ к защищённым endpoint'ам auth-service.

Resource-сервисы не должны использовать эту stateful-проверку. Они должны валидировать access token stateless:

- проверять подпись через JWKS;
- проверять issuer;
- проверять audience;
- проверять expiration;
- читать `uid`, `roles` и при необходимости `client_id`.

Так resource-сервисы остаются независимыми от persistence-слоя auth-service. Logout и бан сразу отзывают refresh/session
state в auth-service, а уже выпущенные access tokens остаются валидными в resource-сервисах до короткого срока истечения.

Проверка активного бана централизована в `UserBanService`. Если позже потребуется мгновенно применять бан во внешних
сервисах, поверх этой точки можно добавить introspection endpoint, API gateway или публикацию revocation events.
