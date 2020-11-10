package com.loicdev.springdemo.controller;

import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import com.loicdev.springdemo.service.DatabaseIntegrityViolationException;
import com.loicdev.springdemo.service.ResourceAlreadyExistsException;
import com.loicdev.springdemo.service.ResourceNotFoundException;
import com.loicdev.springdemo.service.ResourceStorageException;

@ControllerAdvice
public class RestResponseEntityExceptionHandler extends ResponseEntityExceptionHandler {

	@ExceptionHandler({ResourceNotFoundException.class})
    public ResponseEntity<Object> handleNotFoundException(Exception exception, WebRequest request){

        return new ResponseEntity<Object>("Resource Not Found", new HttpHeaders(), HttpStatus.NOT_FOUND);
    }
	
    @ExceptionHandler({ResourceAlreadyExistsException.class})
    @ResponseStatus(HttpStatus.FORBIDDEN)
    @ResponseBody
    public ValidationErrorResponse handleAlreadyExistsException(Exception exception, WebRequest request){
    	ValidationErrorResponse error = new ValidationErrorResponse();
        error.getViolations().add(
        		new Violation(exception.getMessage(), " Data already exists")
        	);
        return error;
    }
    
    @ExceptionHandler(ConstraintViolationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ResponseBody
    public ValidationErrorResponse onConstraintValidationException(ConstraintViolationException e) {
      ValidationErrorResponse error = new ValidationErrorResponse();
      for (ConstraintViolation<?> violation : e.getConstraintViolations()) {
    	  error.getViolations().add(
    			  new Violation(violation.getPropertyPath().toString(), violation.getMessage()));
      }
      return error;
    }
    
    @ExceptionHandler({ResourceStorageException.class})
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ResponseBody
    public ValidationErrorResponse onResourceStorageException(ResourceStorageException e) {
    	ValidationErrorResponse error = new ValidationErrorResponse();
        error.getViolations().add(
        		new Violation(e.getMessage(), e.getCause().toString())
        	);
        return error;
    }
    
    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {
    	ValidationErrorResponse error = new ValidationErrorResponse();
    	for (FieldError fieldError : ex.getBindingResult().getFieldErrors()) {
    		error.getViolations().add(new Violation(fieldError.getField(), fieldError.getDefaultMessage()));
    	}
        return handleExceptionInternal(ex, error, headers, HttpStatus.BAD_REQUEST, request);
    }
    
    @ExceptionHandler({DatabaseIntegrityViolationException.class})
    @ResponseStatus(HttpStatus.CONFLICT)
    @ResponseBody
    public ValidationErrorResponse handleDataIntegrityViolationException(Exception exception, WebRequest request){
    	ValidationErrorResponse error = new ValidationErrorResponse();
    	error.getViolations().add(
    			new Violation(exception.getMessage(), " vérifiez les différentes entités pouvant être liées à celui-ci"));
    	return error;
    }
}