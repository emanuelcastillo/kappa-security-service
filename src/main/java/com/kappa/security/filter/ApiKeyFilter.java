package com.kappa.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;


public class ApiKeyFilter /* extends OncePerRequestFilter */ {


    /*
    private final String API_KEY_VALUE = "apikeyexample";

    private final String API_KEY_HEADER = "api_key";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try{
            final var apiOptionalKey = Optional.of(request.getHeader(API_KEY_HEADER));
            final var apiKey = apiOptionalKey.orElseThrow(() -> new BadCredentialsException("no header key invalida"));
            if(!apiKey.equals(API_KEY_VALUE)){
                throw new BadCredentialsException("Api key invalida");
            }
        }
        catch (Exception e){
            throw new BadCredentialsException("Api key invalida");
        }
        filterChain.doFilter(request, response);
    }
     */
}
