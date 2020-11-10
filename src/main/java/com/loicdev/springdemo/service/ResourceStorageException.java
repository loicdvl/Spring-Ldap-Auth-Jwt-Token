package com.loicdev.springdemo.service;

public class ResourceStorageException extends RuntimeException {

	private static final long serialVersionUID = -277253270058091931L;

	public ResourceStorageException() {
	}
	
	public ResourceStorageException(String message) {
		super(message);
	}
	
	public ResourceStorageException(String message, Throwable cause) {
		super(message, cause);
	}
	
	public ResourceStorageException(Throwable cause) {
		super(cause);
	}
	
	public ResourceStorageException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}
}
