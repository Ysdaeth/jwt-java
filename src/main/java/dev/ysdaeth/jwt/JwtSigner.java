package dev.ysdaeth.jwt;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;

abstract class JwtSigner {

    private static final JwtClaimsSerializer serializer = new JwtClaimsSerializer();
    private final JwtAlgorithm algorithm;

    /**
     * see {@link JwtAlgorithm}
     * @param algorithm algorithm name {@link JwtAlgorithm}
     */
    protected JwtSigner(JwtAlgorithm algorithm){
        this.algorithm = algorithm;
        JwtSignerFactory.register(algorithm,this);
    }

    /**
     * Creates Jwt signature, then set it as the jwt field, finally returns serialized base64 JWT
     * @param jwt jwt instance to create and set signature
     * @param key key to sign
     * @return serialized base64 encoded JWT token
     */
    final String sign(Jwt jwt, Key key) throws MalformedJwtException {
        Header header = jwt.getHeader();
        header.setAlgorithm( algorithm.name() );
        header.setType("JWT");
        String headerBase64 = serializer.serializeToBase64(header.getClaims());

        Payload payload = jwt.getPayload();
        if(payload.getIssuedAt() == null) payload.setIssuedAt(Instant.now());
        String payloadBase64 = serializer.serializeToBase64(payload.getClaims());

        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder
                .append(headerBase64)
                .append('.')
                .append(payloadBase64);

        byte[] headerPayloadBytes = stringBuilder.toString().getBytes(StandardCharsets.UTF_8);
        Signature signature = createSignature(headerPayloadBytes, key);
        String signatureBase64 = serializer.bytesToBase64(signature.getBytes());
        stringBuilder
                .append('.')
                .append(signatureBase64);
        jwt.setSignature(signature);

        return stringBuilder.toString();
    }

    protected abstract Signature createSignature(byte[] message, Key key);
    protected abstract boolean verify(byte[] message, Signature signature, Key key);

    final Jwt verify(String jwtBase64, Key key) throws MalformedJwtException, SecurityException {
        String headerBase64 = extractHeaderBase64(jwtBase64);
        String payloadBase64 = extractPayloadBase64(jwtBase64);
        String mergedClaims = headerBase64 + '.' + payloadBase64;
        byte[] message = mergedClaims.getBytes(StandardCharsets.UTF_8);

        String signatureBase64 = extractSignatureBase64(jwtBase64);
        Signature signature = new Signature(signatureBase64);

        boolean isValid = verify(message, signature, key);
        if(!isValid) throw new SecurityException("Invalid Jwt");

        Claims headerClaims = serializer.deserializeClaimsBase64(headerBase64);
        Claims payloadClaims = serializer.deserializeClaimsBase64(payloadBase64);

        Header header = new Header(headerClaims);
        Payload payload = new Payload(payloadClaims);

        return new Jwt(header, payload, signature);
    }

    static Header getUnsafeHeader(String serializedJwt) throws MalformedJwtException {
        String headerBase64 = extractHeaderBase64(serializedJwt);
        Claims headerClaims = serializer.deserializeClaimsBase64(headerBase64);
        return new Header(headerClaims);
    }

    private static String extractHeaderBase64(String jwtBase64){
        int dotAfter = jwtBase64.indexOf('.');
        return extractBase64(jwtBase64, 0, dotAfter);
    }
    private static String extractPayloadBase64(String jwtBase64) throws MalformedJwtException {
        int dotBefore = jwtBase64.indexOf('.');
        int dotAfter = jwtBase64.lastIndexOf('.');
        return extractBase64(jwtBase64, dotBefore + 1 , dotAfter);
    }

    private static String extractSignatureBase64(String jwtBase64) throws MalformedJwtException {
        int dotBefore = jwtBase64.lastIndexOf('.');
        return extractBase64(jwtBase64, dotBefore + 1, jwtBase64.length());
    }

    /**
     * Extract part of the string, if fails throws {@link MalformedJwtException}
     * @param jwtBase64 full serialized JSON Web Token.
     * @param start string index inclusive
     * @param end string index exclusive
     * @return substring
     * @throws MalformedJwtException when failed to find
     */
    private static String extractBase64(String jwtBase64, int start, int end) throws MalformedJwtException {
        String base64;
        try{
            base64 = jwtBase64.substring(start, end);
        }catch (Exception e){
            throw new MalformedJwtException("Signature extraction failed. " + e.getMessage(), e);
        }
        return base64;
    }
}
