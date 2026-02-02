package com.project.budget_manager.security.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
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
}
