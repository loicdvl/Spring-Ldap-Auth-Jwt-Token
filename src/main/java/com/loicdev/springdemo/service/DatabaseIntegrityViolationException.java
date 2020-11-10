package com.loicdev.springdemo.service;

public class DatabaseIntegrityViolationException extends RuntimeException {

	private static final long serialVersionUID = -6547546936555971825L;

	public DatabaseIntegrityViolationException() {
    }

    public DatabaseIntegrityViolationException(String message) {
        super(message);
    }

    public DatabaseIntegrityViolationException(String message, Throwable cause) {
        super(message, cause);
    }

    public DatabaseIntegrityViolationException(Throwable cause) {
        super(cause);
    }

    public DatabaseIntegrityViolationException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
