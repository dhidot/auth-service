package com.commerce.auth.exception;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 22:29
Version 1.0
*/

import com.commerce.auth.common.ApiResponse;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleValidationException(
            MethodArgumentNotValidException ex) {

        Map<String, String> errors = new LinkedHashMap<>();

        ex.getBindingResult()
                .getFieldErrors()
                .forEach(error ->
                        errors.put(error.getField(), error.getDefaultMessage()));

        ApiResponse<Map<String, String>> response = ApiResponse.<Map<String, String>>builder()
                .code("400")
                .message("Validation failed")
                .data(errors)
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ApiResponse<Object>> handleBadRequest(BadRequestException ex) {

        return ResponseEntity.badRequest().body(
                ApiResponse.builder()
                        .code("400")
                        .message(ex.getMessage())
                        .data(null)
                        .build()
        );
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiResponse<Object>> handleNotFound(ResourceNotFoundException ex) {

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                ApiResponse.builder()
                        .code("404")
                        .message(ex.getMessage())
                        .data(null)
                        .build()
        );
    }

    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<ApiResponse<Object>> handleUnauthorized(UnauthorizedException ex) {

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                ApiResponse.builder()
                        .code("401")
                        .message(ex.getMessage())
                        .data(null)
                        .build()
        );
    }

    @ExceptionHandler(ConflictException.class)
    public ResponseEntity<ApiResponse<Void>> handleConflict(
            ConflictException ex
    ) {

        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(
                        ApiResponse.<Void>builder()
                                .code("409")
                                .message(ex.getMessage())
                                .build()
                );
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiResponse<Void>> handleDataIntegrityViolation(
            DataIntegrityViolationException ex
    ) {

        String constraintName = null;

        Throwable cause = ex;

        while (cause != null) {

            if (cause instanceof
                    org.hibernate.exception.ConstraintViolationException
                            constraintException) {

                constraintName = constraintException.getConstraintName();
                break;
            }

            cause = cause.getCause();
        }

        String message;

        if ("users_email_key".equals(constraintName)) {

            message = "Email already registered";

        } else if ("users_username_key".equals(constraintName)) {

            message = "Username already registered";

        } else {

            // Bukan constraint yang sudah kita kenali.
            // Jangan ubah semua database error menjadi 409.
            throw ex;
        }

        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(
                        ApiResponse.<Void>builder()
                                .code("409")
                                .message(message)
                                .build()
                );
    }

}