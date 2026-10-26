package dev.ysdaeth.jwt;

import java.security.Key;

/**
 * Functional interface to obtain key based on the provided unsafe JwtHeader
 */
@FunctionalInterface
public interface KeyLocator {
    /**
     * Based on the provided header, this function should return key to verify signature
     * of the JWT Signature
     * @param unsafeHeader unsafe, not verified JWT header
     * @return Key to verify JWT signature.
     */
    Key findKey(JwtHeader unsafeHeader);
}
