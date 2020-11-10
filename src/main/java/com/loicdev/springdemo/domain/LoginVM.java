package com.loicdev.springdemo.domain;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

import lombok.Data;

@Data
public class LoginVM {

	@NotBlank
	@Size(min = 1, max = 50)
	private String username;
	
	@NotBlank
	@Size(min = 4, max = 100)
	private String password;
	
	private Boolean rememberMe;

	@Override
	public String toString() {
		return "LoginVM [username=" + username + ", password=" + password + ", rememberMe=" + rememberMe + "]";
	}
}
