package com.example.demoapp.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class UserServiceException extends RuntimeException {
    private static final long serialVersionUID = 8735234234L;

    public UserServiceException(String message) {
        super(String.format("Error saving user: [%s]", message));
    }
}
