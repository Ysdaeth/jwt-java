package dev.ysdaeth.jwt;

import java.util.HashMap;
import java.util.Map;

class JwtSignerFactory {

    private final static Map<JwtAlgorithm,JwtSigner> signers = new HashMap<>();
    static{
        signers.put(JwtAlgorithm.HS256, new JwtSignerHS256());
        signers.put(JwtAlgorithm.RS256, new JwtSignerRS256());
    }

    static void register(JwtAlgorithm jwtAlgorithm, JwtSigner signer){
        if(signers.get(jwtAlgorithm) != null) throw new RuntimeException(
                "Jwt algorithm '%s' is already registered.".formatted(jwtAlgorithm));
        signers.put(jwtAlgorithm, signer);
    }

    /**
     * Registered signer if exists, otherwise null
     * @param jwtAlgorithm Jwt algorithm
     * @return instance or null
     */
    static JwtSigner getInstance(JwtAlgorithm jwtAlgorithm){
        return signers.get(jwtAlgorithm);
    }
}
