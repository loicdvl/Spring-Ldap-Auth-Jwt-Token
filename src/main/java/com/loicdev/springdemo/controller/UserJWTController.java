package com.loicdev.springdemo.controller;

import javax.validation.Valid;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.loicdev.springdemo.domain.LoginVM;
import com.loicdev.springdemo.security.JWTFilter;
import com.loicdev.springdemo.security.JwtTokenProvider;

@RestController
@RequestMapping("/api")
public class UserJWTController {

	private final JwtTokenProvider tokenProvider;
	
	private final AuthenticationManagerBuilder authenticationManagerBuilder;

	public UserJWTController(JwtTokenProvider tokenProvider,
			AuthenticationManagerBuilder authenticationManagerBuilder) {
		this.tokenProvider = tokenProvider;
		this.authenticationManagerBuilder = authenticationManagerBuilder;
	}
	
	@PostMapping("/authenticate")
	public ResponseEntity<JWTToken> authorize(@Valid @RequestBody LoginVM loginVM){
		
		UsernamePasswordAuthenticationToken authenticationToken =
				new UsernamePasswordAuthenticationToken(loginVM.getUsername(), loginVM.getPassword());
	
		SecurityContextHolder.getContext().setAuthentication(null);
		Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		boolean rememberMe = (loginVM.getRememberMe() == null) ? false : loginVM.getRememberMe();
		String jwt = tokenProvider.generateToken(authentication, rememberMe);
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add(JWTFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);
		return new ResponseEntity<>(new JWTToken(jwt), httpHeaders, HttpStatus.OK);
	}
	
	static class JWTToken {
		private String idToken;
		
		JWTToken(String idToken) {
			this.idToken = idToken;
		}
		
		@JsonProperty("id_token")
		String getIdToken() {
			return idToken;
		}
		
		void setIdToken(String idToken) {
			this.idToken = idToken;
		}
	}
}
