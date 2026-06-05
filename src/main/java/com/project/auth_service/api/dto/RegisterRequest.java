package com.project.auth_service.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RegisterRequest {
    @NotBlank
    @Size(min=3,max=64)
    private String username;

    @NotBlank
    @Size(min=8,max=72)
    private String password;

    @NotBlank
    @Size(max=128)
    private String email;

    private String clientId;
}
