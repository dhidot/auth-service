package com.commerce.auth.utils;

/*
@Author Didot
Created on 26/07/2026
@Last Modified on 26/07/2026 00:27
Version 1.0
*/

import jakarta.servlet.http.HttpServletRequest;

public final class RequestUtils {


    private RequestUtils() {
    }


    public static String getClientIp(
            HttpServletRequest request
    ) {

        String xfHeader =
                request.getHeader(
                        "X-Forwarded-For"
                );


        if (xfHeader != null
                && !xfHeader.isBlank()) {

            return xfHeader.split(",")[0];

        }


        return request.getRemoteAddr();
    }


    public static String getDeviceInfo(
            HttpServletRequest request
    ) {

        return request.getHeader(
                "User-Agent"
        );

    }

}
