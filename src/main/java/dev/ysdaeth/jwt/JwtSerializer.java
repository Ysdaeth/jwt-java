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
    private final TypeReference<HashMap<String, String>> claimsTypeRef
            = new TypeReference<HashMap<String, String>>() {};

    JwtSerializer(){
        mapper = JsonMapper.builder()
                .addModule(new BlackbirdModule())
                .build();
    }

    String concatSerialized(Header header, Payload payload, Signature signature){
        try{
            return header.getBase64() + "." + payload.getBase64() + "." + signature.getBase64();
        }catch (Exception e){
            throw new RuntimeException("Failed to serialize Jwt." + e.getMessage(), e);
        }
    }

    String serialize(Header header){
        String serializedHeader = mapper.writeValueAsString( header.getClaims() );
        return toBase64( serializedHeader );
    }

    String serialize(Payload payload){
        String serializedPayload = mapper.writeValueAsString( payload.getClaims() );
        return toBase64( serializedPayload );
    }

    Jwt deserialize(String serialized) throws JwtStateException {
        String[] parts = serialized.split("//.");
        if(parts.length != 3) throw new JwtStateException(
                "Token must contain three sections, but has: '%d'".formatted(parts.length));

        String serializedHeader = fromBase64(parts[0]);
        Map<String,String> deserializedHeader = mapper.readValue(serializedHeader, claimsTypeRef);
        Header header = new Header().setClaims(deserializedHeader);

        String serializedPayload = fromBase64(parts[1]);
        Map<String,String> deserializedPayload = mapper.readValue(serializedPayload, claimsTypeRef);
        Payload payload = new Payload().setClaims(deserializedPayload);

        Signature signature = new Signature( parts[2] );

        return new Jwt(header, payload, signature);

    }

    private String toBase64(String text){
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        return toBase64(bytes);
    }

    private String toBase64(byte[] bytes){
        return Base64.getEncoder().encodeToString(bytes); }

    private String fromBase64(String base64){
        byte[] bytes = Base64.getDecoder().decode(base64);
        return new String(bytes, StandardCharsets.UTF_8);
    }

}
