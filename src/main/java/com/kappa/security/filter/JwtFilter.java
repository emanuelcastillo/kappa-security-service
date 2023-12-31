package com.kappa.security.filter;

import com.kappa.security.service.JwtUserDetailsService;
import com.kappa.security.service.JwtService;
//import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

//@Component
//@AllArgsConstructor
//@Slf4j
public class JwtFilter /* extends OncePerRequestFilter */ {
    /*
    private final JwtService jwtService;
    private final JwtUserDetailsService jwtUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final var requestCheckToken = request.getHeader("Authorization");
        String username = null;
        String jwt = null;
        if (Objects.nonNull(requestCheckToken)&&requestCheckToken.startsWith("Bearer ")){
            jwt = requestCheckToken.substring(7);
            try {
                username = jwtService.getUsernameFromToken(jwt);
            }
            catch (IllegalArgumentException e){
                System.out.println(e.getMessage());
            }
            catch (ExpiredJwtException e){
               //log.warn(e.getMessage());
                System.out.println(e.getMessage());
            }
        }
        if (Objects.nonNull(username) && Objects.isNull(SecurityContextHolder.getContext().getAuthentication())){
            final var userDetails = this.jwtUserDetailsService.loadUserByUsername(username);
            if (this.jwtService.validateToken(jwt, userDetails)){
                var usernameAndPasswordAuthToken = new UsernamePasswordAuthenticationToken(
                  userDetails, null, userDetails.getAuthorities()
                );
                usernameAndPasswordAuthToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(usernameAndPasswordAuthToken);
            }
        }
        filterChain.doFilter(request, response);
    }
     */
}
