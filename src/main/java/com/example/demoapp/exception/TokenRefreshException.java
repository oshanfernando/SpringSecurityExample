package com.example.demoapp.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.FORBIDDEN)
public class TokenRefreshException extends RuntimeException {

    private static final long serialVersionUID = 1231232131L;

    public TokenRefreshException(String token, String message) {
        super(String.format("Refresh token error: [%s]: %s", token, message));
    }
}