package com.kappa.security.service;

import com.kappa.security.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@AllArgsConstructor
@Service
public class OAuth2UserDetails implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return this.userRepository.findByUsername(username)
                .map(//utilizamos map para obtener el usuario del wrapper Optional
                        userEntity -> {
                            final var authorities = userEntity.getRoles().stream().map(role -> new SimpleGrantedAuthority(role.getRole())).toList();
                            return new User(userEntity.getUsername(), userEntity.getPassword(), authorities);
                        }
                ).orElseThrow(()->new UsernameNotFoundException("El usuario no se encontro"));
    }
}
