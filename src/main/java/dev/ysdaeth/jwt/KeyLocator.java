package dev.ysdaeth.jwt;

import java.security.Key;

@FunctionalInterface
public interface KeyLocator {
    Key findKey(String keyId);
}
