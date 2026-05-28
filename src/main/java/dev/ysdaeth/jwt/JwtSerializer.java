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

    String serialize(Jwt jwt){
        Header header = jwt.getHeader();
        String serializedHeader = mapper.writeValueAsString(header.getClaims());
        String base64Header = toBase64(serializedHeader);

        Payload payload = jwt.getPayload();
        String serializedPayload = mapper.writeValueAsString(payload.getClaims());
        String base64Payload = toBase64(serializedPayload);

        String signature = toBase64(jwt.getSignature().getBytes());

        return base64Header + '.' + base64Payload + '.' + signature;

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
        Payload payload = new Payload().setClaims(deserializedHeader);

        Signature signature = new Signature( parts[2] );

        return new Jwt(header, payload, signature);

    }

    private String toBase64(String claims){
        byte[] bytes = claims.getBytes(StandardCharsets.UTF_8);
        return toBase64(bytes);
    }

    private String toBase64(byte[] bytes){
        return Base64.getEncoder().encodeToString(bytes);
    }

    private String fromBase64(String base64){
        byte[] bytes = Base64.getDecoder().decode(base64);
        return new String(bytes, StandardCharsets.UTF_8);
    }

}
