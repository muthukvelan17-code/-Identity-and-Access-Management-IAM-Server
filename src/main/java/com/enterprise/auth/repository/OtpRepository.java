package com.enterprise.auth.repository;

import com.enterprise.auth.entity.OTP;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface OtpRepository extends JpaRepository<OTP, UUID> {
    Optional<OTP> findFirstByUsernameAndOtpTypeOrderByExpiryTimeDesc(String username, String otpType);
    void deleteByUsernameAndOtpType(String username, String otpType);
}
