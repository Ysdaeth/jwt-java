package dev.ysdaeth.jwt;

public class MalformedTokenException extends Exception {
    public MalformedTokenException(String message) {
        super(message);
    }
}
