package com.kappa.security.service;

//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.security.Keys;
//import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
  /*
    private final long TTL = (60*60);
    private final String SECRET = "5CXM9F93UUqj7y4L/ftqg96Oy1VXiW9FjKyJ3rmyjMU=";

    private Claims getAllClaimsFromToken(String token){
        final var key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }

    public <T> T getClaimsFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Date getExpirationToken(String token){
        return this.getClaimsFromToken(token, Claims::getExpiration);
    }

    private Boolean isExpired(String token){
        final var expirationDate = this.getExpirationToken(token);
        return expirationDate.before(new Date());
    }

    public String generateToken(UserDetails userDetails){
        final Map<String, Object> claims = Collections.singletonMap("ROLES", userDetails.getAuthorities().toString());
        return this.getToken(claims, userDetails.getUsername());
    }
    private String getToken(Map<String, Object> claims, String subject){
        final var key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+ TTL * 1000))
                .signWith(key).compact();
    }
    public String getUsernameFromToken(String token){
        //TODO investigar interfaces funcionale y supliers y la interfaz function
        return this.getClaimsFromToken(token, Claims::getSubject);
    }
    public Boolean validateToken(String token, UserDetails userDetails){
        final var usernameFromUserDetails = userDetails.getUsername();
        final var usernameFromJwt = this.getUsernameFromToken(token);

        return usernameFromUserDetails.equals(usernameFromJwt) && !this.isExpired(token);
    }
   */
}
