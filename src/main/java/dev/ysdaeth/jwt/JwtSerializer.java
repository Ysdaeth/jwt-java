package dev.ysdaeth.jwt;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.module.blackbird.BlackbirdModule;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

class JwtSerializer {
    private final ObjectMapper mapper;
    private final TypeReference<HashMap<String, Object>> claimsTypeRef
            = new TypeReference<HashMap<String, Object>>() {};

    JwtSerializer(){
        mapper = JsonMapper.builder()
                .addModule(new BlackbirdModule())
                .build();
    }

    String serialize(byte[] header, byte[] payload, byte[] signature){
        try{
            String headerBase64 = toBase64( header );
            String payloadBase64 = toBase64( payload );
            String signatureBase64 = toBase64( signature );

            return headerBase64 + "." + payloadBase64 + "." + signatureBase64;

        }catch (Exception e){
            throw new RuntimeException("Failed to serialize Jwt." + e.getMessage(), e);
        }
    }

    Header extractHeader(String serializedJwt) throws MalformedJwtException {
        int indexOfDot = serializedJwt.indexOf('.');
        Claims claims = extractClaims( serializedJwt, 0, indexOfDot);
        return new Header(claims);
    }

    byte[] extractHeaderBytes(String serializedJwt) throws MalformedJwtException{
        int indexOfDot = serializedJwt.indexOf('.');
        return extractClaimsBytes(serializedJwt,0,indexOfDot);
    }

    byte[] serializeToBytes(Header header){
        String serializedHeader = mapper.writeValueAsString( header.getClaims() );
        return serializedHeader.getBytes(StandardCharsets.UTF_8);
    }

    Header deserializeHeaderFromBytes(byte[] header){
        String headerSerialized = new String(header, StandardCharsets.UTF_8);
        Map<String,Object> claims = mapper.convertValue(headerSerialized, claimsTypeRef);
        return new Header(claims);
    }

    Payload extractPayload(String serializedJwt) throws MalformedJwtException {
        int dotBefore = serializedJwt.indexOf('.');
        int dotAfter = serializedJwt.lastIndexOf('.');
        Claims claims = extractClaims(serializedJwt, dotBefore + 1, dotAfter);
        return new Payload(claims);
    }

    byte[] extractPayloadBytes(String serializedJwt) throws MalformedJwtException{
        int dotBefore = serializedJwt.indexOf('.');
        int dotAfter = serializedJwt.lastIndexOf('.');
        return extractClaimsBytes(serializedJwt, dotBefore, dotAfter);
    }

    byte[] serializeToBytes(Payload payload){
        String serializedPayload = mapper.writeValueAsString( payload.getClaims() );
        return serializedPayload.getBytes(StandardCharsets.UTF_8);
    }

    Payload deserializePayloadFromBytes(byte[] payload){
        String headerSerialized = new String(payload, StandardCharsets.UTF_8);
        Map<String,Object> claims = mapper.convertValue(headerSerialized, claimsTypeRef);
        return new Payload(claims);
    }

    Signature extractSignature(String serializedJwt) throws MalformedJwtException {
        int dotBefore = serializedJwt.lastIndexOf('.');
        Signature signature;
        try{
            String base64 = serializedJwt.substring(dotBefore + 1);
            signature = new Signature(base64);
        }catch (Exception e){
            throw new MalformedJwtException("Signature extraction failed. " + e.getMessage(), e);
        }
        return signature;
    }

    byte[] extractSignatureBytes(String serializedJwt) throws MalformedJwtException {
        int dotBefore = serializedJwt.lastIndexOf('.');
        byte[] signature;
        try{
            signature = extractClaimsBytes(serializedJwt, dotBefore +1, serializedJwt.length());
        }catch (Exception e){
            throw new MalformedJwtException("Signature extraction failed. " + e.getMessage(), e);
        }
        return signature;
    }

    /**
     * Extract token claims from serialized JSON Web Token beginning from inclusive start
     * up to exclusive end.
     * @param serializedJwt full serialized JWT token
     * @param start inclusive index of string
     * @param end exclusive index of string
     * @return map of claims
     * @throws MalformedJwtException when extracting claims fail.
     */
    private Claims extractClaims(String serializedJwt, int start, int end)
            throws MalformedJwtException {
        Map<String,Object> claims;
        try{
            String serializedClaims = serializedJwt.substring(start, end);
            claims = mapper.convertValue(serializedClaims, claimsTypeRef);
        }catch (Exception e){
            throw new MalformedJwtException("Json Web Token claims extraction failed."+ e.getMessage(), e);
        }
        return new Claims(claims);
    }

    private byte[] extractClaimsBytes(String serializedJwt, int start, int end)
            throws MalformedJwtException {
        byte[] claims;
        try{
            String serializedClaims = serializedJwt.substring(start,end);
            claims = Base64.getDecoder().decode(serializedClaims);
        }catch (Exception e){
            throw new MalformedJwtException("Json Web Token claims extraction failed."+ e.getMessage(), e);
        }
        return claims;
    }


    private String toBase64(byte[] bytes){
        return Base64.getEncoder().encodeToString(bytes); }

    private String fromBase64(String base64){
        byte[] bytes = Base64.getDecoder().decode(base64);
        return new String(bytes, StandardCharsets.UTF_8);
    }

}
