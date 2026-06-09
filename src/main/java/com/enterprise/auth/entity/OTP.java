package com.enterprise.auth.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "otps")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OTP {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private String code;

    @Column(name = "otp_type", nullable = false)
    private String otpType; // SMS, EMAIL

    @Column(name = "expiry_time", nullable = false)
    private LocalDateTime expiryTime;

    @Column(nullable = false)
    private int attempts;

    public boolean isExpired() {
        return expiryTime.isBefore(LocalDateTime.now());
    }
}
