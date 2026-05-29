package dev.ysdaeth.jwt;

import java.security.Key;
import java.time.Instant;

abstract class JwtSigner {

    private static final JwtSerializer serializer = new JwtSerializer();
    private final String algorithm;

    protected JwtSigner(JwtAlgorithm algorithm){
        this.algorithm = algorithm.name();
        JwtSignerFactory.register(algorithm,this);
    }

    String sign(Jwt jwt, Key key){
        Header header = jwt.getHeader();
        header.setAlgorithm( algorithm );
        byte[] headerBytes = serializer.serializeToBytes(header);

        Payload payload = jwt.getPayload();
        payload.setIssuedAt(Instant.now());
        byte[] payloadBytes = serializer.serializeToBytes(payload);

        Signature signature = createSignature(headerBytes, payloadBytes, key);
        jwt.setSignature(signature);

        String serialized = serializer.serialize(headerBytes, payloadBytes, signature.getBytes());

        payload.getClaims().lock();
        header.getClaims().lock();

        return serialized;
    }

    protected abstract Signature createSignature(byte[] header, byte[] payload, Key key);
    protected abstract boolean verify(byte[] header, byte[] payload, byte[] signature, Key key);

    Jwt verify(String serializedJwt, Key key) throws MalformedJwtException, SecurityException {
        byte[] headerBytes = serializer.extractHeaderBytes(serializedJwt);
        byte[] payloadBytes = serializer.extractPayloadBytes(serializedJwt);
        byte[] signatureBytes = serializer.extractSignatureBytes(serializedJwt);

        boolean isValid = verify(headerBytes, payloadBytes, signatureBytes, key);
        if(!isValid) throw new SecurityException("invalid Jwt");

        Header header = serializer.deserializeHeaderFromBytes(headerBytes);
        Payload payload = serializer.deserializePayloadFromBytes(payloadBytes);
        Signature signature = new Signature(signatureBytes);

        return new Jwt(header, payload, signature);
    }

    static Header getUnsafeHeader(String serializedJwt) throws MalformedJwtException {
        return serializer.extractHeader(serializedJwt);
    }

    static Payload getUnsafePayload(String serializedJwt){
        return serializer.extractPayload(serializedJwt);
    }

    static Signature getUnsafeSignature(String serializedJwt){
        return serializer.extractSignature(serializedJwt);
    }
}
