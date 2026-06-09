package dev.ysdaeth.jwt.exception;

/**
 * Thrown when algorithm or type is not supported
 */
public class JwtUnsupportedException extends JwtSecurityException{
    public JwtUnsupportedException(String message) {
        super(message);
    }

    public JwtUnsupportedException(String message, Throwable cause) {
        super(message, cause);
    }
}
