package com.enterprise.auth.controller;

import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@Controller
public class ConsentController {
    
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationConsentService authorizationConsentService;

    public ConsentController(RegisteredClientRepository registeredClientRepository,
                             OAuth2AuthorizationConsentService authorizationConsentService) {
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationConsentService = authorizationConsentService;
    }

    @GetMapping("/oauth2/consent")
    public String consent(Principal principal, Model model,
                          @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
                          @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
                          @RequestParam(OAuth2ParameterNames.STATE) String state) {

        Set<String> scopesToApprove = new HashSet<>();
        Set<String> previouslyApprovedScopes = new HashSet<>();
        
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        
        if (registeredClient == null) {
            throw new IllegalArgumentException("Invalid client id");
        }
        
        OAuth2AuthorizationConsent currentConsent =
                this.authorizationConsentService.findById(registeredClient.getId(), principal.getName());

        if (currentConsent != null) {
            previouslyApprovedScopes = currentConsent.getScopes();
        }

        for (String scopeFromRequest : StringUtils.delimitedListToStringArray(scope, " ")) {
            if (!previouslyApprovedScopes.contains(scopeFromRequest)) {
                scopesToApprove.add(scopeFromRequest);
            }
        }

        model.addAttribute("clientId", clientId);
        model.addAttribute("clientName", registeredClient.getClientName());
        model.addAttribute("state", state);
        model.addAttribute("scopes", scopesToApprove);
        model.addAttribute("previouslyApprovedScopes", previouslyApprovedScopes);
        model.addAttribute("principalName", principal.getName());

        return "consent";
    }
}
