package dev.ysdaeth.jwt;

public class JwtStateException extends RuntimeException{
    public JwtStateException(String message) {
        super(message);
    }

    public JwtStateException(String message, Throwable cause) {
        super(message, cause);
    }
}
