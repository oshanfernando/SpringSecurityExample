package com.example.demoapp.service;

import com.example.demoapp.entity.RefreshToken;
import com.example.demoapp.entity.Role;
import com.example.demoapp.entity.User;
import com.example.demoapp.enums.ERole;
import com.example.demoapp.exception.UserServiceException;
import com.example.demoapp.model.AuthSuccessDTO;
import com.example.demoapp.model.LoginDTO;
import com.example.demoapp.model.SignupDTO;
import com.example.demoapp.repository.RoleRepository;
import com.example.demoapp.repository.UserRepository;
import com.example.demoapp.security.JwtUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserService {
    private static final Logger LOG = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;

    @Autowired
    public UserService(UserRepository userRepository, RoleRepository roleRepository, @Lazy PasswordEncoder encoder, @Lazy AuthenticationManager authenticationManager, JwtUtils jwtUtils, RefreshTokenService refreshTokenService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.encoder = encoder;
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
        this.refreshTokenService = refreshTokenService;
    }

    public void saveUser(SignupDTO signUpDTO) {
        if (userRepository.existsByUsername(signUpDTO.getUsername())) {
            LOG.error("User already exists by username : {}", signUpDTO.getUsername());
            throw new UserServiceException("User already exists");
        }

        if (userRepository.existsByEmail(signUpDTO.getEmail())) {
            LOG.error("Email is already in use");
            throw new UserServiceException("Email is already in use");
        }

        User user = new User(signUpDTO.getUsername(), signUpDTO.getEmail(),
                encoder.encode(signUpDTO.getPassword()), "DIRECT");

        Set<String> strRoles = signUpDTO.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                if ("admin".equals(role)) {
                    Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                    roles.add(adminRole);
                } else {
                    Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                    roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);
    }

    public User saveOauthUser(SignupDTO signUpDTO) {
        Optional<User> userOptional = userRepository.findByEmail(signUpDTO.getEmail());

        if (userOptional.isPresent()) {
            User dbUser = userOptional.get();
            if (!dbUser.getProvider().equals(signUpDTO.getProvider())) {
                LOG.error("User previously signed up with a different sign in method");
                throw new UserServiceException("You have previously signed up with a different sign in method");
            }
            return dbUser;
        } else {
            if (userRepository.existsByUsername(signUpDTO.getUsername())) {
                LOG.error("Username already taken");
                throw new UserServiceException("Username already taken");
            }

            User user = new User(signUpDTO.getUsername(), signUpDTO.getEmail(),
                    encoder.encode(signUpDTO.getPassword()), signUpDTO.getProvider());

            Set<String> strRoles = signUpDTO.getRole();
            Set<Role> roles = new HashSet<>();

            if (strRoles == null) {
                Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                roles.add(userRole);
            } else {
                strRoles.forEach(role -> {
                    if ("admin".equals(role)) {
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);
                    } else {
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                    }
                });
            }

            user.setRoles(roles);
            return userRepository.save(user);
        }
    }

    public AuthSuccessDTO loginUser(LoginDTO loginDTO) {
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginDTO.getUsername(), loginDTO.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        String jwt = jwtUtils.generateJwtToken(userDetails);

        List<String> roles = userDetails.getAuthorities()
                .stream()
                .map(SimpleGrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

        return new AuthSuccessDTO(jwt, refreshToken.getToken(), userDetails.getId(),
                userDetails.getUsername(), userDetails.getEmail(), roles);
    }
}
