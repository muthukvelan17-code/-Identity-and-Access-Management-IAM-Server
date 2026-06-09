package com.enterprise.auth.service;

import de.taimos.totp.TOTP;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;

@Service
@RequiredArgsConstructor
public class MfaService {

    // Helper to generate a new base32 secret for TOTP
    public String generateSecretKey() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[20];
        random.nextBytes(bytes);
        Base32 base32 = new Base32();
        return base32.encodeToString(bytes);
    }

    // Generate Google Authenticator compatible TOTP code based on a secret
    public String getTOTPCode(String secretKey) {
        Base32 base32 = new Base32();
        byte[] bytes = base32.decode(secretKey);
        String hexKey = Hex.encodeHexString(bytes);
        return TOTP.getOTP(hexKey);
    }

    // Verify user inputted TOTP code matches the generated code
    public boolean verifyTotp(String secretKey, String userCode) {
        String serverCode = getTOTPCode(secretKey);
        return serverCode.equals(userCode);
    }

    // Placeholder for SMS logic via Twilio
    public void sendSmsOtp(String phoneNumber, String otp) {
        // Implementation logic using Twilio API
        System.out.println("Sending OTP " + otp + " via SMS to " + phoneNumber);
    }

    // Placeholder for Email logic via SendGrid
    public void sendEmailOtp(String email, String otp) {
        // Implementation logic using SendGrid API
        System.out.println("Sending OTP " + otp + " via Email to " + email);
    }
}
