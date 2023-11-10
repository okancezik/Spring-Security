package com.okancezik.security.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.okancezik.security.config.JwtService;
import com.okancezik.security.entity.Role;
import com.okancezik.security.entity.User;
import com.okancezik.security.repository.UserRepository;
import com.okancezik.security.requests.AuthenticationRequest;
import com.okancezik.security.requests.RegisterRequest;
import com.okancezik.security.responses.AuthenticationResponse;
import com.okancezik.security.token.Token;
import com.okancezik.security.token.TokenRepository;
import com.okancezik.security.token.TokenType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;

import javax.servlet.http.Cookie;
import java.io.IOException;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest registerRequest) {
        var user = User.builder()
                .firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .role(Role.USER)
                .build();

        var savedUser = userRepository.save(user);

        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(savedUser, jwtToken);

        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationRequest.getEmail(),
                        authenticationRequest.getPassword()
                )
        );

        var user = userRepository.findByEmail(authenticationRequest.getEmail()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user,jwtToken);

        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();

    }

    private void revokeAllUserTokens(User user){
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());

        if(validUserTokens.isEmpty()){
            return;
        }
        validUserTokens.forEach(t->{
            t.setRevoked(true);
            t.setExpired(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();

        tokenRepository.save(token);
    }

    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String email;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }

        refreshToken = authHeader.substring("Bearer".length() + 1);
        email = jwtService.extractUsername(refreshToken);

        if (email != null ) {
            var userDetails = this.userRepository.findByEmail(email).orElseThrow();

            if (jwtService.isTokenValid(refreshToken, userDetails)) {
                var accessToken = jwtService.generateToken(userDetails);
                revokeAllUserTokens(userDetails);
                saveUserToken(userDetails,accessToken);
                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }
}
