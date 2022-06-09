package com.example.demoapp.security;

import com.example.demoapp.entity.RefreshToken;
import com.example.demoapp.entity.User;
import com.example.demoapp.exception.UserServiceException;
import com.example.demoapp.model.SignupDTO;
import com.example.demoapp.service.RefreshTokenService;
import com.example.demoapp.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;
import java.util.UUID;

@Component
public class OauthSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger LOG = LoggerFactory.getLogger(OauthSuccessHandler.class);

    private final UserService userService;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;

    @Autowired
    public OauthSuccessHandler(UserService userService, JwtUtils jwtUtils, RefreshTokenService refreshTokenService) {
        this.userService = userService;
        this.jwtUtils = jwtUtils;
        this.refreshTokenService = refreshTokenService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        DefaultOidcUser oauthUser = (DefaultOidcUser) authentication.getPrincipal();
        LOG.info("=======================================");
        LOG.info("{}", oauthUser);
        LOG.info("================= Saving user ======================");

        SignupDTO signupDTO = new SignupDTO();
        signupDTO.setProvider(String.valueOf(oauthUser.getIssuer()));
        signupDTO.setUsername(oauthUser.getEmail());
        signupDTO.setEmail(oauthUser.getEmail());
        // set random password if required
        signupDTO.setPassword(UUID.randomUUID().toString());
        // set default role ROLE_USER
        signupDTO.setRole(Set.of("user"));
        try {
            User user = userService.saveOauthUser(signupDTO);
            String accessToken = jwtUtils.generateTokenFromUsername(signupDTO.getUsername());
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

            String redirectUrl = "/app/oauth/callback/success?accessToken=" + accessToken + "&refreshToken="
                    + refreshToken.getToken();

            response.sendRedirect(redirectUrl);
        } catch (UserServiceException e) {
            response.sendRedirect("/app/oauth/callback/error?message=" + e);
        }
    }
}
