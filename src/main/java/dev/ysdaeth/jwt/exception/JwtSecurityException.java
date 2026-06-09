package dev.ysdaeth.jwt.exception;

/**
 * Jwt general security exception
 */
public class JwtSecurityException extends RuntimeException {

    public JwtSecurityException(String message) {
        super(message);
    }

    public JwtSecurityException(String message, Throwable cause) {
        super(message, cause);
    }
}
