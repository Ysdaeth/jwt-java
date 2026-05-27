package dev.ysdaeth.jwt;

import java.util.HashMap;
import java.util.Map;

class JwtSignerFactory {

    private final static Map<JwtType,JwtSigner> signers = new HashMap<>();

    static void register(JwtType jwtType, JwtSigner signer){
        if(signers.get(jwtType) != null) throw new RuntimeException(
                "Jwt Type '%s' is already registered or taken".formatted(jwtType));
        signers.put(jwtType, signer);
    }

    static JwtSigner getInstance(JwtType jwtType){
        JwtSigner signer =  signers.get(jwtType);
        if(signer == null) throw new RuntimeException("No such JwtSigner: '%s'".formatted(jwtType));
        return signer;
    }
}
