package com.okancezik.security.services;

import com.okancezik.security.entity.User;
import com.okancezik.security.repository.UserRepository;
import com.okancezik.security.requests.ChangePasswordRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;

@Service
@RequiredArgsConstructor
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    public void changePassword(ChangePasswordRequest changePasswordRequest, Principal connectedUser) {
        var user = (User) ((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal();

        // check if the current password is correct
        // log.info(user.getPassword())
        if(!passwordEncoder.matches(changePasswordRequest.getCurrentPassword(), user.getPassword())){
            throw new IllegalStateException("Wrong password");
        }

        // check if the two new passwords are the same
        if(!(changePasswordRequest.getNewPassword().equals(changePasswordRequest.getConfirmationPassword()))){
            throw new IllegalStateException("Passwords are not same");
        }

        // update the password
        user.setPassword(passwordEncoder.encode(changePasswordRequest.getNewPassword()));

        // save the password
        userRepository.save(user);
    }
}
