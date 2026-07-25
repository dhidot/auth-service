package com.commerce.auth.exception;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 22:28
Version 1.0
*/

public class ResourceNotFoundException extends RuntimeException {

    public ResourceNotFoundException(String message) {
        super(message);
    }

}