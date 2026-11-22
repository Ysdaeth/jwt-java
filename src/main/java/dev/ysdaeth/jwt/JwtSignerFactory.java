package dev.ysdaeth.jwt;

import dev.ysdaeth.jwt.exception.JwtUnsupportedException;

import java.security.Key;
import java.util.HashMap;
import java.util.Map;

class JwtSignerFactory {

    private final static Map<Object,JwtSigner> keyAlgorithmSigners = new HashMap<>();
    static {
        keyAlgorithmSigners.put(JwtAlgorithm.HS256, new JwtMacSigner(JwtAlgorithm.HS256,"HmacSHA256"));
        keyAlgorithmSigners.put(JwtAlgorithm.HS384, new JwtMacSigner(JwtAlgorithm.HS384,"HmacSHA384"));
        keyAlgorithmSigners.put(JwtAlgorithm.HS512, new JwtMacSigner(JwtAlgorithm.HS512,"HmacSHA512"));

        keyAlgorithmSigners.put(JwtAlgorithm.RS256, new JwtRsaSigner(JwtAlgorithm.RS256, "SHA256withRSA"));
        keyAlgorithmSigners.put(JwtAlgorithm.RS384, new JwtRsaSigner(JwtAlgorithm.RS256, "SHA384withRSA"));
        keyAlgorithmSigners.put(JwtAlgorithm.RS512, new JwtRsaSigner(JwtAlgorithm.RS256, "SHA512withRSA"));
    }

    static JwtSigner getInstance(JwtAlgorithm jwtAlgorithm) throws JwtUnsupportedException {
        JwtSigner signer =  keyAlgorithmSigners.get(jwtAlgorithm);
        if(signer == null) throw new JwtUnsupportedException(
                "There is no such registered jwt algorithm '%s'".formatted(jwtAlgorithm.name())
        );
        return signer;
    }
}
