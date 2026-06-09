package dev.ysdaeth.jwt.exception;

/**
 * Thrown when JWT is expired
 */
public class JwtExpiredException extends JwtSecurityException{

    public JwtExpiredException(String message) {
        super(message);
    }

    public JwtExpiredException(String message, Throwable cause) {
        super(message, cause);
    }
}
