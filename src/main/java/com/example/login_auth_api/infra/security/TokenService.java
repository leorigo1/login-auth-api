package com.example.login_auth_api.infra.security;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.example.login_auth_api.domain.user.User;



@Service
public class TokenService {
	@Value("${api.security.token.secret}")
	private String secret;
	
	public String GenerateToken (User user) {
		try {
			Algorithm algorithm = Algorithm.HMAC256(secret);
			
			String Token = JWT.create()
						   .withIssuer("login-auth-api")
						   .withSubject(user.getEmail())
						   .withExpiresAt(generateExpirationDate())
						   .sign(algorithm);
			return Token;
		}
		catch(JWTCreationException e){
			throw new RuntimeException("Erro ao autenticar");
		}
	}
	
	public String validateToken(String token) {
		try {
			Algorithm algorithm = Algorithm.HMAC256(secret);
			return JWT.require(algorithm)
				   .withIssuer("login-auth-api")
				   .build()
				   .verify(token)
				   .getSubject();
		}
		catch(JWTVerificationException e) {
			return null;
		}
	}
	
	private Instant generateExpirationDate() {
	    return ZonedDateTime.now(ZoneId.systemDefault())
	            .plusHours(2)
	            .toInstant();
	}
}
