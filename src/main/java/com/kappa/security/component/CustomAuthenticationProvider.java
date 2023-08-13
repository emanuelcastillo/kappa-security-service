package com.kappa.security.component;

import com.kappa.security.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

//@Component
//@AllArgsConstructor
public class CustomAuthenticationProvider /* implements AuthenticationProvider  */{

    /*
    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final var username = authentication.getName();
        final var password = authentication.getCredentials().toString();
        final var userFromDb = this.userRepository.findByUsername(username);
        final var user = userFromDb.orElseThrow(() -> new BadCredentialsException("Usuario y/o contrasena incorrecta"));
        final var userPwd = user.getPassword();
        if (passwordEncoder.matches(password, userPwd)){
            final var roles = user.getRoles();
            //TODO investigar el strema y map y lamda expresion
            final var authorities = roles.stream().map(role -> new SimpleGrantedAuthority(role.getRole())).collect(Collectors.toList());
            return new UsernamePasswordAuthenticationToken(username, password, authorities);
        }
        else {
            throw new BadCredentialsException("Usuario y/o contrasena incorrecta");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
     */
}
