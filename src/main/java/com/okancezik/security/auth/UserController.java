package com.okancezik.security.auth;

import com.okancezik.security.requests.ChangePasswordRequest;
import com.okancezik.security.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PatchMapping
    public ResponseEntity<?> changePassword(
            @RequestBody ChangePasswordRequest changePasswordRequest,
            Principal connectedUser
    ){
        userService.changePassword(changePasswordRequest, connectedUser);
        return ResponseEntity.ok().build();
    }
}
