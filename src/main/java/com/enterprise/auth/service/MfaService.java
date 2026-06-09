package com.enterprise.auth.service;

import de.taimos.totp.TOTP;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;

import com.sendgrid.Method;
import com.sendgrid.Request;
import com.sendgrid.Response;
import com.sendgrid.SendGrid;
import com.sendgrid.helpers.mail.Mail;
import com.sendgrid.helpers.mail.objects.Content;
import com.sendgrid.helpers.mail.objects.Email;

import java.io.IOException;
import java.security.SecureRandom;

@Service
@RequiredArgsConstructor
@Slf4j
public class MfaService {

    @Value("${mfa.twilio.account-sid:}")
    private String twilioAccountSid;

    @Value("${mfa.twilio.auth-token:}")
    private String twilioAuthToken;

    @Value("${mfa.twilio.phone-number:}")
    private String twilioFromNumber;

    @Value("${mfa.sendgrid.api-key:}")
    private String sendGridApiKey;

    @Value("${mfa.sendgrid.from-email:no-reply@enterprise.com}")
    private String sendGridFromEmail;

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

    // SMS logic via Twilio
    public void sendSmsOtp(String phoneNumber, String otp) {
        if (twilioAccountSid.isEmpty() || twilioAuthToken.isEmpty() || twilioFromNumber.isEmpty()) {
            log.warn("[LOCAL DEV FALLBACK] SMS OTP to {}: {}", phoneNumber, otp);
            System.out.println("Sending OTP " + otp + " via SMS to " + phoneNumber);
            return;
        }

        try {
            Twilio.init(twilioAccountSid, twilioAuthToken);
            Message.creator(
                    new PhoneNumber(phoneNumber),
                    new PhoneNumber(twilioFromNumber),
                    "Your enterprise verification code is: " + otp
            ).create();
            log.info("Twilio SMS OTP sent successfully to {}", phoneNumber);
        } catch (Exception e) {
            log.error("Failed to send Twilio SMS OTP to {}: {}", phoneNumber, e.getMessage());
        }
    }

    // Email logic via SendGrid
    public void sendEmailOtp(String email, String otp) {
        if (sendGridApiKey.isEmpty()) {
            log.warn("[LOCAL DEV FALLBACK] Email OTP to {}: {}", email, otp);
            System.out.println("Sending OTP " + otp + " via Email to " + email);
            return;
        }

        Email from = new Email(sendGridFromEmail);
        String subject = "Your Enterprise Verification Code";
        Email to = new Email(email);
        Content content = new Content("text/plain", "Your verification code is: " + otp);
        Mail mail = new Mail(from, subject, to, content);

        SendGrid sg = new SendGrid(sendGridApiKey);
        Request request = new Request();
        try {
            request.setMethod(Method.POST);
            request.setEndpoint("mail/send");
            request.setBody(mail.build());
            Response response = sg.api(request);
            log.info("SendGrid Email OTP sent successfully to {} (Status Code: {})", email, response.getStatusCode());
        } catch (IOException ex) {
            log.error("Failed to send SendGrid Email OTP to {}: {}", email, ex.getMessage());
        }
    }
}
