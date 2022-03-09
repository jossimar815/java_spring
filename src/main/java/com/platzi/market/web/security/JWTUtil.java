package com.platzi.market.web.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JWTUtil {
    private static final String KEY = "platzi";

    public String generateToken(UserDetails userDetails){
        return Jwts.builder().setSubject(userDetails.getUsername())//usuario
                .setIssuedAt(new Date())//fecha de creacion
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))// fecha expira
                .signWith(SignatureAlgorithm.HS256, KEY).compact();
    }

    public boolean validateToken(String token, UserDetails userDetails){//validar si el token es correcto,
        return userDetails.getUsername().equals(extractUsername(token)) &&
                !isTokenExpired(token);
    }

    public String extractUsername(String token){
                                //usuario de la peticion
        return getClaims(token).getSubject();
    }

    public boolean isTokenExpired(String token){
        return getClaims(token).getExpiration().before(new Date());
    }

    private Claims getClaims(String token){  //verificar que este creado para el usuario y que no este vencido. son objetos dentro del jwt
        return Jwts.parser().setSigningKey(KEY).parseClaimsJws(token).getBody();
    }
}
