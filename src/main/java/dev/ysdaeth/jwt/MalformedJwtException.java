package dev.ysdaeth.jwt;

public class MalformedJwtException extends RuntimeException{
    public MalformedJwtException(String message) {
        super(message);
    }

    public MalformedJwtException(String message, Throwable cause) {
        super(message, cause);
    }
}
