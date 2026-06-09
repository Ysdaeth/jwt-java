package dev.ysdaeth.jwt.exception;

public class JwtMalformedException extends JwtSecurityException{
    public JwtMalformedException(String message) {
        super(message);
    }

    public JwtMalformedException(String message, Throwable cause) {
        super(message, cause);
    }
}
