package com.project.auth_service.service;

import com.project.auth_service.enums.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AppUserDetailsService implements UserDetailsService {
    private final AuthUserService authUserService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var userOptional = authUserService.findByUsername(username);
        if (userOptional.isEmpty()) {
            throw new UsernameNotFoundException(username);
        }
        var user = userOptional.get();

        var authorities = user.roles().stream()
                .map(Role::authority)
                .map(SimpleGrantedAuthority::new)
                .toList();

        return User.builder()
                .username(user.username())
                .password(user.passwordHash())
                .authorities(authorities)
                .build();
    }
}
