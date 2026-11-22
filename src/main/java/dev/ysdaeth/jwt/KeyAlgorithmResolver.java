package dev.ysdaeth.jwt;

import java.security.Key;
import java.util.Map;

public class KeyAlgorithmResolver {

    private static final Map<String, JwtAlgorithm> ALGORITHMS = Map.of(
            "RSA", JwtAlgorithm.RS256,
            "HMAC", JwtAlgorithm.HS256,
            "HmacSHA256", JwtAlgorithm.HS256,
            "HmacSHA384", JwtAlgorithm.HS384,
            "HmacSHA512", JwtAlgorithm.HS512
    );

    public static JwtAlgorithm resolveAlgorithm(Key key) {
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }

        String algorithm = key.getAlgorithm();

        JwtAlgorithm jwtAlgorithm = ALGORITHMS.get(algorithm);

        if (jwtAlgorithm == null) {
            throw new IllegalArgumentException(
                    "Unsupported key algorithm: " + algorithm
            );
        }

        return jwtAlgorithm;
    }
}
