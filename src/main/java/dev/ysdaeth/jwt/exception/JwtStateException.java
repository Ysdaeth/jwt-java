package dev.ysdaeth.jwt.exception;

public class JwtStateException extends RuntimeException {
    public JwtStateException(String message) {
        super(message);
    }
}
