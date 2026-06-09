package dev.ysdaeth.jwt.exception;

/**
 * Thrown when signature does not match
 */
public class JwtSignatureException extends JwtSecurityException{
    public JwtSignatureException(String message) {
        super(message);
    }

    public JwtSignatureException(String message, Throwable cause) {
        super(message, cause);
    }
}
