package com.enterprise.auth.controller;

import com.enterprise.auth.entity.AuditLog;
import com.enterprise.auth.entity.Role;
import com.enterprise.auth.entity.User;
import com.enterprise.auth.repository.AuditLogRepository;
import com.enterprise.auth.repository.RoleRepository;
import com.enterprise.auth.repository.UserRepository;
import com.enterprise.auth.service.TokenRevocationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuditLogRepository auditLogRepository;
    private final TokenRevocationService tokenRevocationService;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok(userRepository.findAll());
    }

    @PostMapping("/roles")
    public ResponseEntity<?> createRole(@RequestParam String roleName) {
        if (roleRepository.existsByRoleName(roleName)) {
            return ResponseEntity.badRequest().body("Role already exists");
        }
        Role role = new Role();
        role.setRoleName(roleName);
        roleRepository.save(role);
        return ResponseEntity.ok("Role created successfully: " + roleName);
    }

    @GetMapping("/audit")
    public ResponseEntity<List<AuditLog>> getAuditLogs() {
        return ResponseEntity.ok(auditLogRepository.findAll());
    }

    @PostMapping("/revoke")
    public ResponseEntity<?> forceRevokeToken(@RequestParam String token, @RequestParam long expirationMs) {
        tokenRevocationService.blacklistToken(token, expirationMs);
        return ResponseEntity.ok("Token successfully blacklisted/revoked by admin");
    }
}
