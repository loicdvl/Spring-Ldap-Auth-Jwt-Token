package com.loicdev.springdemo.security;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

public class AppUserDetails extends User {

	private static final long serialVersionUID = 3000038732509478732L;

	private String serialNumber;

	private List<String> profiles;

	public AppUserDetails(String username, String serialNumber, List<String> profiles, Collection<? extends GrantedAuthority> authorities) {
		super(username, "1", authorities);
		this.serialNumber = serialNumber;
		this.profiles = profiles;
	}

	public String getSerialNumber() {
		return serialNumber;
	}

	public void setSerialNumber(String serialNumber) {
		this.serialNumber = serialNumber;
	}

	public List<String> getProfiles() {
		return profiles;
	}

	public void setProfiles(List<String> profiles) {
		this.profiles = profiles;
	}
}
