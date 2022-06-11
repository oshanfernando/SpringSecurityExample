package com.example.demoapp.controller;

import javax.validation.Valid;

import com.example.demoapp.entity.RefreshToken;
import com.example.demoapp.exception.TokenRefreshException;
import com.example.demoapp.model.*;
import com.example.demoapp.security.JwtUtils;
import com.example.demoapp.service.RefreshTokenService;
import com.example.demoapp.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/app")
public class AuthenticationController {
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;
    private final UserService userService;

    public AuthenticationController(JwtUtils jwtUtils, RefreshTokenService refreshTokenService, UserService userService) {
        this.jwtUtils = jwtUtils;
        this.refreshTokenService = refreshTokenService;
        this.userService = userService;
    }

    @PostMapping("/login")
    public ResponseEntity<AuthSuccessDTO> authenticateUser(@Valid @RequestBody LoginDTO loginDTO) {
        return ResponseEntity.ok(userService.loginUser(loginDTO));
    }

    @PostMapping("/register")
    public ResponseEntity<StringResponseDTO> registerUser(@Valid @RequestBody SignupDTO signUpDTO) {
        userService.saveUser(signUpDTO);
        return ResponseEntity.ok(new StringResponseDTO("User registered successfully!"));
    }

    @PostMapping("/refreshtoken")
    public ResponseEntity<TokenRefreshResponseDTO> refreshtoken(@Valid @RequestBody RefreshTokenDTO request) {
        String requestRefreshToken = request.getRefreshToken();

        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String token = jwtUtils.generateTokenFromUsername(user.getUsername());
                    return ResponseEntity.ok(new TokenRefreshResponseDTO(token, requestRefreshToken));
                })
                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
                        "Refresh token is not in database!"));
    }

    @GetMapping(value = "/oauth/callback/success")
    public ResponseEntity<AuthSuccessDTO> callbackSuccess(@RequestParam("accessToken") String accessToken,
                                                          @RequestParam("refreshToken") String refreshToken) {
        AuthSuccessDTO responseDTO = new AuthSuccessDTO();
        responseDTO.setAccessToken(accessToken);
        responseDTO.setRefreshToken(refreshToken);
        responseDTO.setTokenType("Bearer");
        return ResponseEntity.ok(responseDTO);
    }

    @GetMapping(value = "/oauth/callback/error")
    public ResponseEntity<StringResponseDTO> callbackError(@RequestParam("message") String message) {
        return new ResponseEntity<>(new StringResponseDTO(message), HttpStatus.UNAUTHORIZED);
    }

}
