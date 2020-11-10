package com.loicdev.springdemo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.loicdev.springdemo.security.JWTConfigurer;
import com.loicdev.springdemo.security.JwtAuthenticationEntryPoint;
import com.loicdev.springdemo.security.JwtTokenProvider;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwtAuthenticationEntryPoint unauthorizedHandler;
        
    private final JwtTokenProvider tokenProvider;
    
    public SecurityConfig(JwtAuthenticationEntryPoint unauthorizedHandler,
    		JwtTokenProvider tokenProvider) {
    	this.unauthorizedHandler = unauthorizedHandler;
    	this.tokenProvider = tokenProvider;
    }
    
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    	auth
    		.ldapAuthentication()
    			.userDnPatterns("uid={0},ou=people")
    			.groupSearchBase("ou=groups")
    			.contextSource()
    				.url("ldap://localhost:8389/dc=springframework,dc=org")
    				.and()
    			.passwordCompare()
    				.passwordEncoder(new BCryptPasswordEncoder())
    				.passwordAttribute("userPassword");
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Override
    public void configure(WebSecurity web) {
    	web.ignoring()
    		.antMatchers(HttpMethod.OPTIONS, "/**")
    		.antMatchers("/api/**/*.{js,html}")
    		.antMatchers("/i18n/**")
    		.antMatchers("/content/**")
    		.antMatchers("/swagger-ui/index.html")
    		.antMatchers("/test/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf()
            .disable()
            .exceptionHandling()
            .authenticationEntryPoint(unauthorizedHandler)
        .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
            .authorizeRequests()
                .antMatchers("/api/authenticate/**").permitAll()
                .antMatchers(HttpMethod.GET, "/api/**").permitAll()
                .antMatchers(HttpMethod.POST, "/api/**").hasAnyAuthority("ROLE_MANAGERS", "ROLE_DEVELOPERS")
                .antMatchers(HttpMethod.PUT, "/api/**").hasAnyAuthority("ROLE_MANAGERS", "ROLE_DEVELOPERS")
                .antMatchers(HttpMethod.DELETE, "/api/**").hasAnyAuthority("ROLE_MANAGERS", "ROLE_DEVELOPERS")
                .antMatchers(HttpMethod.PATCH, "/api/**").hasAnyAuthority("ROLE_MANAGERS", "ROLE_DEVELOPERS")
                .anyRequest().authenticated()
        .and()
        	.httpBasic()
        .and()
        	.apply(securityConfigurerAdapter());
    }
    
    private JWTConfigurer securityConfigurerAdapter() {
    	return new JWTConfigurer(tokenProvider);
    }
}