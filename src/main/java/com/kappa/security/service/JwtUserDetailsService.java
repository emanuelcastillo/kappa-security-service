package com.kappa.security.service;

import com.kappa.security.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

//@Service //COMO ANADI ESTA NOTACION, SPRING SE ENCARGA DE CARGAR EL SERVICIO AL CONTENEDOR
//@Transactional//NOS INDICA QUE VAMOS A REALIZAR TRANSACCIONES A LA BASE DE DATOS
//@AllArgsConstructor//NOTACION DE LOMBOK PARA CREAR EL CONSTRUCTOR AUTOMATICAMENTE
public class JwtUserDetailsService /* implements UserDetailsService */ {

    //si no estamos usando lombok tenemos que craer el constructor para que se inyecte la dependencia
    //y ya no le tenemos que anadir @autowired porque spring boot lo hace desde la version anterior
    /*
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
     */
}
