package com.enterprise.auth.controller;

import com.enterprise.auth.dto.LoginRequest;
import com.enterprise.auth.dto.RegisterRequest;
import com.enterprise.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest request) {
        authService.register(request);
        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser() {
        // Here you would add logic to blacklist the token in Redis
        return ResponseEntity.ok("Logged out successfully");
    }
    @GetMapping("/profile")
    public ResponseEntity<?> getUserProfile(java.security.Principal principal) {
        return ResponseEntity.ok(authService.getProfile(principal.getName()));
    }

    @PostMapping("/reset-password-request")
    public ResponseEntity<?> requestPasswordReset(@RequestParam String email) {
        authService.requestPasswordReset(email);
        return ResponseEntity.ok("Password reset link sent to email");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String token, @RequestParam String newPassword) {
        authService.resetPassword(token, newPassword);
        return ResponseEntity.ok("Password reset successfully");
    }
}
