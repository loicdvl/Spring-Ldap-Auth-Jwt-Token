package com.loicdev.springdemo.service;

public class ResourceAlreadyExistsException extends RuntimeException {

	private static final long serialVersionUID = -8355002436269314459L;

	public ResourceAlreadyExistsException() {
	}
	
	public ResourceAlreadyExistsException(String message) {
		super(message);
	}
	
	public ResourceAlreadyExistsException(String message, Throwable cause) {
		super(message, cause);
	}
	
	public ResourceAlreadyExistsException(Throwable cause) {
		super(cause);
	}
	
	public ResourceAlreadyExistsException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}
}
