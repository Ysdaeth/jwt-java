package dev.ysdaeth.jwt;

import dev.ysdaeth.jwt.exception.JwtMalformedException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.module.blackbird.BlackbirdModule;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Uses Jackson Blackbird module for map serialization. Class is responsible to
 * serialize and deserialize claims of JSON Web Token
 */
class JwtClaimsSerializer {
    private final ObjectMapper mapper;
    private final TypeReference<HashMap<String, Object>> claimsTypeRef
            = new TypeReference<HashMap<String, Object>>() {};

    JwtClaimsSerializer(){
        mapper = JsonMapper.builder()
                .addModule(new BlackbirdModule())
                .build();
    }

    /**
     * Takes map of the claims and serializes it to string,
     * then makes that string base64 url safe encoded bytes representation
     * @param claims JWT Claims
     * @return Serialized Map converted to base64 byte representation
     */
    String serializeToBase64(JwtClaims claims){
        Map<String,Object> claimsMap = claims.getMap();
        String serialized = mapper.writeValueAsString(claimsMap);
        byte[] serializedBytes = serialized.getBytes(StandardCharsets.UTF_8);
        return JwtBytesPolicy.bytesToBase64(serializedBytes);
    }

    /**
     * Converts base64 encoded JWT bytes claims to string, then deserialize it to Claims
     * @param claimsBase64 base64 map of claims
     * @return deserialized claims
     * @throws JwtMalformedException when base64 format is illegal, or cannot be parsed by Jackson module
     */
    JwtClaims deserializeClaimsBase64(String claimsBase64) throws JwtMalformedException {
        JwtClaims claims;
        try{
            byte[] claimsBytes = JwtBytesPolicy.bytesFromBase64(claimsBase64);
            String serializedClaims = new String(claimsBytes, StandardCharsets.UTF_8);
            Map<String, Object> claimsMap = mapper.readValue(serializedClaims, claimsTypeRef);
            claims = new JwtClaims(claimsMap);
        }catch (Exception e){
            throw new JwtMalformedException("JSON Web Token claims deserialization failed. "+ e.getMessage(), e);
        }
        return claims;
    }

}
