package com.enterprise.auth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class AuditService {

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        String username = event.getAuthentication().getName();
        log.info("AUDIT - Successful login for user: {}", username);
        
        // Track Token Generation Events
        if (event.getAuthentication() instanceof OAuth2AccessTokenAuthenticationToken) {
            log.info("AUDIT - Token generated for client: {}", username);
        }
    }

    @EventListener
    public void onAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
        String username = event.getAuthentication().getName();
        String exceptionMessage = event.getException().getMessage();
        log.warn("AUDIT - Failed login attempt for user: {}. Reason: {}", username, exceptionMessage);
    }
}
