package com.okancezik.security.services;

import com.okancezik.security.config.JwtService;
import com.okancezik.security.entity.Role;
import com.okancezik.security.entity.User;
import com.okancezik.security.repository.UserRepository;
import com.okancezik.security.requests.AuthenticationRequest;
import com.okancezik.security.requests.RegisterRequest;
import com.okancezik.security.responses.AuthenticationResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@RequiredArgsConstructor
@Service
public class AuthenticationService {

    private final UserRepository userRepository;
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

        userRepository.save(user);

        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {

        try {
            authenticationManager.authenticate(
                   new UsernamePasswordAuthenticationToken(
                           authenticationRequest.getEmail(),
                           authenticationRequest.getPassword()
                   )
            );
            var user = userRepository.findByEmail(authenticationRequest.getEmail()).orElseThrow();
            var jwtToken = jwtService.generateToken(user);

            return AuthenticationResponse.builder()
                    .token(jwtToken)
                    .build();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }
}
