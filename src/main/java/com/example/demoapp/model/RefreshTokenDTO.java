package com.example.demoapp.model;

import javax.validation.constraints.NotBlank;

public class RefreshTokenDTO {
    @NotBlank
    private String refreshToken;

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
