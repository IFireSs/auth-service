package com.project.budget_manager.security.exception_handler;

import com.project.budget_manager.security.cookie.RefreshCookieFactory;
import com.project.budget_manager.security.cookie.SessionIdCookieFactory;
import com.project.budget_manager.security.exceptions.BadCredentialsException;
import com.project.budget_manager.security.exceptions.EmailAlreadyExistsException;
import com.project.budget_manager.security.exceptions.ExpiredRefreshTokenException;
import com.project.budget_manager.security.exceptions.InvalidRefreshTokenException;
import com.project.budget_manager.security.exceptions.RefreshTokenReuseDetectedException;
import com.project.budget_manager.security.exceptions.UsernameAlreadyExistsException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RequiredArgsConstructor
@RestControllerAdvice
public class ExceptionAuthHandler {
    private final RefreshCookieFactory refreshCookieFactory;
    private final SessionIdCookieFactory sessionIdCookieFactory;

    @ExceptionHandler({InvalidRefreshTokenException.class,
            ExpiredRefreshTokenException.class,
            RefreshTokenReuseDetectedException.class,
            BadCredentialsException.class,
            UsernameAlreadyExistsException.class,
            EmailAlreadyExistsException.class})
    public ResponseEntity<?> handleRefreshAuth(RuntimeException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .header(HttpHeaders.SET_COOKIE, refreshCookieFactory.clearRefreshCookie().toString())
                .header(HttpHeaders.SET_COOKIE, sessionIdCookieFactory.clearSessionIdCookie().toString()).body(ex.getMessage());
    }
}
