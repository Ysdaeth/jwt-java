package dev.ysdaeth.jwt;

import dev.ysdaeth.jwt.exception.JwtUnsupportedException;

import java.util.HashMap;
import java.util.Map;

class JwtSignerFactory {

    private final static Map<JwtAlgorithm,JwtSigner> signers = new HashMap<>();
    static{
        signers.put(JwtAlgorithm.HS256, new JwtSignerHS256());
        signers.put(JwtAlgorithm.RS256, new JwtSignerRS256());
    }

    /**
     * Registered signer if exists, otherwise null
     * @param jwtAlgorithm Jwt algorithm
     * @return instance or null
     */
    static JwtSigner getInstance(JwtAlgorithm jwtAlgorithm){
        JwtSigner signer =  signers.get(jwtAlgorithm);
        if(signer == null) throw new JwtUnsupportedException(
                "There is no such registered jwt algorithm '%s'".formatted(jwtAlgorithm.name())
        );
        return signer;
    }
}
