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
    private final com.enterprise.auth.service.OtpService otpService;
    private final com.enterprise.auth.service.TokenRevocationService tokenRevocationService;

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
    public ResponseEntity<?> logoutUser(jakarta.servlet.http.HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");
        if (headerAuth != null && headerAuth.startsWith("Bearer ")) {
            String jwt = headerAuth.substring(7);
            tokenRevocationService.blacklistToken(jwt, 3600000L); // Blacklist for 1 hour
        }
        return ResponseEntity.ok("Logged out successfully");
    }

    @GetMapping("/profile")
    public ResponseEntity<?> getUserProfile(java.security.Principal principal) {
        return ResponseEntity.ok(authService.getProfile(principal.getName()));
    }

    @PutMapping("/profile")
    public ResponseEntity<?> updateUserProfile(java.security.Principal principal, @RequestParam String email) {
        authService.updateProfile(principal.getName(), email);
        return ResponseEntity.ok("Profile updated successfully");
    }

    @DeleteMapping("/profile")
    public ResponseEntity<?> deleteUserProfile(java.security.Principal principal) {
        authService.deleteAccount(principal.getName());
        return ResponseEntity.ok("Account deleted successfully");
    }

    @PostMapping("/password")
    public ResponseEntity<?> changePassword(java.security.Principal principal, @RequestParam String oldPassword, @RequestParam String newPassword) {
        authService.changePassword(principal.getName(), oldPassword, newPassword);
        return ResponseEntity.ok("Password updated successfully");
    }

    @PostMapping("/mfa/enable")
    public ResponseEntity<?> enableMfa(java.security.Principal principal) {
        authService.toggleMfa(principal.getName(), true);
        return ResponseEntity.ok("MFA enabled successfully");
    }

    @PostMapping("/mfa/disable")
    public ResponseEntity<?> disableMfa(java.security.Principal principal) {
        authService.toggleMfa(principal.getName(), false);
        return ResponseEntity.ok("MFA disabled successfully");
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestParam String refreshToken) {
        return ResponseEntity.ok(authService.refreshToken(refreshToken));
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

    @PostMapping("/send-otp")
    public ResponseEntity<?> sendOtp(@RequestParam String username, @RequestParam String target, @RequestParam String type) {
        otpService.generateAndSendOtp(username, target, type);
        return ResponseEntity.ok("OTP sent successfully");
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOtp(@RequestParam String username, @RequestParam String code, @RequestParam String type) {
        boolean isValid = otpService.verifyOtp(username, code, type);
        if (isValid) {
            return ResponseEntity.ok("OTP verified successfully");
        } else {
            return ResponseEntity.badRequest().body("Invalid or expired OTP");
        }
    }
}
