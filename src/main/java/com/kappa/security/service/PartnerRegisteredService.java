package com.kappa.security.service;

import com.kappa.security.repository.PartnersRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Arrays;

@Service
@AllArgsConstructor
public class PartnerRegisteredService implements RegisteredClientRepository {

    private PartnersRepository partnersRepository;

    @Override
    public RegisteredClient findByClientId(String clientId) {

        var partnerOptional = this.partnersRepository.findByClientId(clientId);
        if (partnerOptional.isPresent()) {
            return partnerOptional.map(partner -> {
                var authorizationGrantTypes = Arrays.stream(partner.getGrantTypes().split(","))
                        .map(AuthorizationGrantType::new).toList();
                System.out.print(authorizationGrantTypes);
                var clientAuthenticationMethods = Arrays.stream(partner.getAuthenticationMethods().split(","))
                        .map(ClientAuthenticationMethod::new).toList();
                System.out.print(clientAuthenticationMethods);
                var scopes = Arrays.stream(partner.getScopes().split(",")).toList();
                System.out.print(scopes);
                return RegisteredClient
                        .withId(partner.getId().toString())
                        .clientId(partner.getClientId())
                        .clientSecret(partner.getClientSecret())
                        .clientName(partner.getClientName())
                        .redirectUri(partner.getRedirectUri())
                        .postLogoutRedirectUri(partner.getRedirectUriLogout())
                        .clientAuthenticationMethod(clientAuthenticationMethods.get(0))
                        .clientAuthenticationMethod(clientAuthenticationMethods.get(1))
                        .scope(scopes.get(0))
                        .scope(scopes.get(1))
                        .authorizationGrantType(authorizationGrantTypes.get(0))
                        .authorizationGrantType(authorizationGrantTypes.get(1))
                        .tokenSettings(this.tokenSettings())
                        .build();
            }).orElseThrow(()->new BadCredentialsException("invalid token"));
        } else {
            throw new BadCredentialsException("invalid token");
        }
    }

    @Override
    public void save(RegisteredClient registeredClient) {}

    @Override
    public RegisteredClient findById(String id) {
        return null;
    }

    private TokenSettings tokenSettings(){
        return TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(8)).build();
    }
}
