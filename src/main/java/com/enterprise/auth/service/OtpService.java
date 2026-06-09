package com.enterprise.auth.service;

import com.enterprise.auth.entity.OTP;
import com.enterprise.auth.repository.OtpRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class OtpService {

    private final OtpRepository otpRepository;
    private final MfaService mfaService;
    private static final int OTP_VALID_DURATION_MINUTES = 5;
    private static final int MAX_OTP_ATTEMPTS = 3;

    @Transactional
    public void generateAndSendOtp(String username, String target, String type) {
        // Clear previous OTPs of the same type
        otpRepository.deleteByUsernameAndOtpType(username, type);

        // Generate a 6-digit secure numeric code
        SecureRandom random = new SecureRandom();
        String code = String.valueOf(100000 + random.nextInt(900000));

        OTP otp = OTP.builder()
                .username(username)
                .code(code)
                .otpType(type)
                .expiryTime(LocalDateTime.now().plusMinutes(OTP_VALID_DURATION_MINUTES))
                .attempts(0)
                .build();

        otpRepository.save(otp);

        // Dispatch OTP via Twilio or SendGrid using MfaService
        if ("SMS".equalsIgnoreCase(type)) {
            mfaService.sendSmsOtp(target, code);
        } else if ("EMAIL".equalsIgnoreCase(type)) {
            mfaService.sendEmailOtp(target, code);
        } else {
            throw new IllegalArgumentException("Unsupported OTP dispatch channel: " + type);
        }
    }

    @Transactional
    public boolean verifyOtp(String username, String code, String type) {
        Optional<OTP> otpOpt = otpRepository.findFirstByUsernameAndOtpTypeOrderByExpiryTimeDesc(username, type);

        if (otpOpt.isEmpty()) {
            return false;
        }

        OTP otp = otpOpt.get();

        if (otp.isExpired()) {
            otpRepository.delete(otp);
            return false;
        }

        if (otp.getAttempts() >= MAX_OTP_ATTEMPTS) {
            otpRepository.delete(otp);
            return false;
        }

        otp.setAttempts(otp.getAttempts() + 1);
        otpRepository.save(otp);

        if (otp.getCode().equals(code)) {
            otpRepository.delete(otp);
            return true;
        }

        return false;
    }
}
