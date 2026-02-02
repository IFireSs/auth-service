package com.project.budget_manager.security.exception_handler;

import com.project.budget_manager.security.exceptions.BadCredentialsException;
import com.project.budget_manager.security.exceptions.ExpiredRefreshTokenException;
import com.project.budget_manager.security.exceptions.InvalidRefreshTokenException;
import com.project.budget_manager.security.exceptions.RefreshTokenReuseDetectedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ExceptionAuthHandler {

    @ExceptionHandler({InvalidRefreshTokenException.class,
            ExpiredRefreshTokenException.class,
            RefreshTokenReuseDetectedException.class,
            BadCredentialsException.class})
    public ResponseEntity<?> handleRefreshAuth(RuntimeException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ex.getMessage());
    }
}
