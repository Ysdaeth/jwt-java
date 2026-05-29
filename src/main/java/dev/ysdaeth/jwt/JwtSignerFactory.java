package dev.ysdaeth.jwt;

import java.util.HashMap;
import java.util.Map;

class JwtSignerFactory {

    private final static Map<String,JwtSigner> signers = new HashMap<>();

    static void register(JwtAlgorithm jwtAlgorithm, JwtSigner signer){
        String algName = jwtAlgorithm.name();
        if(signers.get(algName) != null) throw new RuntimeException(
                "Jwt algorithm '%s' is already registered.".formatted(algName));
        signers.put(algName, signer);
    }

    /**
     * Registered signer if exists, otherwise null
     * @param jwtAlgorithm Jwt algorithm
     * @return instance or null
     */
    static JwtSigner getInstance(String jwtAlgorithm){
        JwtSigner signer =  signers.get(jwtAlgorithm);
        if(signer == null) return null;
        return signer;
    }
}
