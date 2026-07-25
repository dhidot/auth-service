package com.commerce.auth.exception;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 22:28
Version 1.0
*/

public class UnauthorizedException extends RuntimeException {

    public UnauthorizedException(String message) {
        super(message);
    }

}