package com.kappa.security.config;

import com.kappa.security.service.OAuth2UserDetails;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {


    private static final String API_PROTECTED_PATH_RESOURCE  = "/api/v1/**";
    private static final String PUBLIC_RESOURCE  = "/public/**";

    private static final String AUTH_WRITE  =  "write";
    private static final String AUTH_READ  =  "read";
    private static final String ROLE_PREMIUM = "PREMIUM";
    private static final String ROLE_BASIC = "BASIC";
    private static final String ROLE_USER = "USER";
    private static final String ROLE_ADMIN = "ADMIN";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SERVICE_CONTEXT = "Authentication kappa service";


   /*
    @Bean
    RegisteredClientRepository clientRepository(){
        var client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("kappa")
                .clientSecret("secret")
                .scope("read")
                .redirectUri("http://localhost:8080")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .build();
        return new InMemoryRegisteredClientRepository(client);
    };
    */

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)///sirve para ordenar los beans de configuracion del contenedor de spring
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);

        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());
        httpSecurity.exceptionHandling(e->e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
        return httpSecurity.build();
    }

    /*
      @Bean
    @Order(2)///sirve para ordenar los beans de configuracion del contenedor de spring
    SecurityFilterChain clientSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity.formLogin(Customizer.withDefaults());
        httpSecurity.authorizeHttpRequests(
                auth -> auth
                        //.requestMatchers(API_PROTECTED_PATH_RESOURCE).hasAnyAuthority(AUTH_WRITE, AUTH_READ)
                        .requestMatchers(API_PROTECTED_PATH_RESOURCE).hasAnyRole(ROLE_ADMIN, ROLE_USER)
                        .anyRequest().permitAll()
        );
        httpSecurity.oauth2ResourceServer(oauth->oauth.jwt(Customizer.withDefaults()));
        return httpSecurity.build();
    }

    @Bean
    @Order(3)///sirve para ordenar los beans de configuracion del contenedor de spring
    SecurityFilterChain userSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity.formLogin(Customizer.withDefaults());
        httpSecurity.authorizeHttpRequests(
                auth -> auth
                        //.requestMatchers(API_PUBLIC_PATH_RESOURCE).permitAll()
                        //.requestMatchers(API_LOGIN_PATH_RESOURCE).permitAll()
                        //.requestMatchers(API_SIGNUP_PATH_RESOURCE).permitAll()
                        //.requestMatchers(API_PROTECTED_PATH_RESOURCE).hasAnyAuthority(AUTH_WRITE, AUTH_READ)
                        .requestMatchers(API_PROTECTED_PATH_RESOURCE).hasAnyRole(ROLE_ADMIN, ROLE_USER)
                        .anyRequest().permitAll()
        );
        httpSecurity.oauth2ResourceServer(oauth->oauth.jwt(Customizer.withDefaults()));
        return httpSecurity.build();
    }
     */


    @Bean
    SecurityFilterChain publicSecurityFilter(HttpSecurity httpSecurity) throws Exception{
        httpSecurity.formLogin(Customizer.withDefaults());
        httpSecurity.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        httpSecurity.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        httpSecurity.logout(Customizer.withDefaults());
        return httpSecurity.build();
    }

    @Bean
    PasswordEncoder passwordEncode(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    DaoAuthenticationProvider AuthenticationProvider(PasswordEncoder encoder, OAuth2UserDetails userDetails){
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setPasswordEncoder(encoder);
        authProvider.setUserDetailsService(userDetails);
        return authProvider;
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings(){
        return AuthorizationServerSettings.builder().build();
    }

    /*
    @Bean
    JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter(){
        var converter = new JwtGrantedAuthoritiesConverter();
        converter.setAuthorityPrefix("");
        return converter;
    }


    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter(){
        var authConverter = new JwtGrantedAuthoritiesConverter();
        authConverter.setAuthoritiesClaimName("roles");
        authConverter.setAuthorityPrefix("");
        var converterResponse = new JwtAuthenticationConverter();
        converterResponse.setJwtGrantedAuthoritiesConverter(authConverter);
        return converterResponse;
    }
     */

    private static KeyPair generateRsa(){
        KeyPair pair;
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            keyPairGenerator.initialize(2048);
            pair = keyPairGenerator.genKeyPair();
        }catch (NoSuchFieldError e){
            throw new IllegalStateException(e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage());
        }
        return pair;
    }

    private static RSAKey generateKeys(){
        var keys = generateRsa();
        var publicKey = (RSAPublicKey) keys.getPublic();
        var privateKey = (RSAPrivateKey) keys.getPrivate(); // Usa getPrivate() para obtener la clave privada

        return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
    }


    @Bean
    JWKSource<SecurityContext> jwkSource(){
        var rsa = generateKeys();
        var jwkSet = new JWKSet(rsa);
        return (selector, securityContext) -> selector.select(jwkSet); // Usa selector.select(jwkSet) para seleccionar claves
    }


    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> source){
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(source);
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer(){
        return context -> {
            var authentication = context.getPrincipal();
            var authorities = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
            if(context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)){
                context.getClaims().claims(claim -> {
                    claim.putAll(
                            Map.of(
                                    "roles", authorities,
                                    "service_context", SERVICE_CONTEXT,
                                    "request_date", LocalDateTime.now().toString()
                            )
                    );
                });
            }

        };
    }
}
