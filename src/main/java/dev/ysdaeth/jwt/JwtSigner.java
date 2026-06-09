package dev.ysdaeth.jwt;

import dev.ysdaeth.jwt.exception.JwtExpiredException;
import dev.ysdaeth.jwt.exception.JwtMalformedException;
import dev.ysdaeth.jwt.exception.JwtSignatureException;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;

abstract class JwtSigner {

    private static final JwtClaimsSerializer serializer = new JwtClaimsSerializer();
    private final JwtAlgorithm algorithm;

    protected JwtSigner(JwtAlgorithm algorithm){
        this.algorithm = algorithm;
    }

    /**
     * Creates Jwt signature, then set it as the jwt field, finally returns serialized base64 JWT
     * @param jwt jwt instance to create and set signature
     * @param key key to sign
     * @return serialized base64 encoded JWT token
     * @throws IllegalArgumentException when passed key does not match algorithm instance i.e.
     * passed Private key when algorithm was HS256, key or JWT was null
     */
    final String sign(Jwt jwt, Key key) throws IllegalArgumentException {
        if(jwt == null) throw new IllegalArgumentException("Jwt object must not be null");
        if(key == null) throw new IllegalArgumentException("Jwt signing key must not be null");

        JwtHeader header = jwt.getHeader();
        header.setAlgorithm(algorithm.name());
        header.setType("JWT");
        String headerBase64 = serializer.serializeToBase64(header.getClaims());

        JwtPayload payload = jwt.getPayload();
        String payloadBase64 = serializer.serializeToBase64(payload.getClaims());;

        String headerPayload = headerBase64 + '.' + payloadBase64;

        byte[] headerAndPayloadBytes = headerPayload.getBytes(StandardCharsets.UTF_8);
        JwtSignature signature = createSignature(headerAndPayloadBytes, key);
        String signatureBase64 = JwtBytesPolicy.bytesToBase64(signature.getBytes());

        String token = headerPayload + '.' + signatureBase64;
        jwt.setSignature(signature);

        return token;
    }

    /**
     * Creates signature for message bytes
     * @param message message to create sign for
     * @param key key to create signature from message
     * @return signature bytes
     * @throws IllegalArgumentException when provided key does not match algorithm instance
     * @throws RuntimeException any other reason which comes from invalid code, missing dependencies, etc.
     */
    protected abstract JwtSignature createSignature(byte[] message, Key key) throws IllegalArgumentException, RuntimeException;

    /**
     * Tests if signature matches the JSON Web Token, and returns parsed {@link Jwt} instance, otherwise throws
     * {@link SecurityException}
     * @param jwtBase64 String form of JSON Web Token base64 encoded
     * @param key key to test if signature matches the header and payload
     * @return verified deserialized Jwt instance.
     * @throws JwtExpiredException When jwt is expired, key is invalid, key type is incorrect, or signature does not match the token
     * @throws JwtMalformedException When jwt is malformed or invalid, i.e. incorrect bytes encoding.
     * @throws JwtSignatureException When jwt signature does not match.
     */
    final Jwt verify(String jwtBase64, Key key) throws JwtExpiredException, JwtMalformedException, JwtSignatureException {
        if(key == null) throw new JwtSignatureException("Jwt verification key was null");
        if(jwtBase64 == null) throw new JwtSignatureException("JSON Web Token was null");

        String[] tokenSections = splitTokenBase64(jwtBase64);

        JwtSignature signature = verify(tokenSections, key);

        String payloadSection = tokenSections[1];
        JwtClaims payloadClaims = serializer.deserializeClaimsBase64(payloadSection);
        JwtPayload payload = new JwtPayload(payloadClaims);

        throwIfExpired(payload);

        String headerSection = tokenSections[0];
        JwtClaims headerClaims = serializer.deserializeClaimsBase64(headerSection);
        JwtHeader header = new JwtHeader(headerClaims);

        return new Jwt(header, payload, signature);
    }

    /**
     * Tests if header and payload matches the signature, if true, then signature is returned, otherwise throws.
     * @param sections sections of the jwt token in standard order: [Header, Payload, Signature]
     * @param key key for verification
     * @throws JwtMalformedException when token is malformed
     * @throws JwtSignatureException when signature does not match
     * @return signature if valid, otherwise null
     */
    private JwtSignature verify(String[] sections, Key key) throws
            JwtMalformedException, JwtSignatureException {

        String merged = sections[0] + "." + sections[1];
        byte[] mergedBytes = merged.getBytes(StandardCharsets.UTF_8);

        byte[] signatureBytes = JwtBytesPolicy.bytesFromBase64(sections[2]);
        JwtSignature signature = new JwtSignature(signatureBytes);
        boolean verified = verifyMessage(mergedBytes, signature, key);
        if(!verified) throw new JwtSignatureException("JSON Web Token signature does not match");
        return signature;
    }

    private static void throwIfExpired(JwtPayload payload) throws JwtExpiredException {
        Instant exp = payload.getExpireAt();
        if(exp == null) return;
        boolean expired = Instant.now().isAfter(exp);
        if(expired) throw new JwtExpiredException("JSON Web Token is expired");
    }

    /**
     * Tests if message matches the signature
     * @param message message to verify
     * @param signature signature to test
     * @param key key to create signature from message
     * @return true if message is verified, otherwise false
     */
    protected abstract boolean verifyMessage(byte[] message, JwtSignature signature, Key key);

    /**
     * Returns header which is not verified, or throws Exception when malformed
     */
    static JwtHeader getUnsafeHeader(String jwtBase64) throws JwtMalformedException {
        int dotAfter = jwtBase64.indexOf('.');
        if(dotAfter == -1) throw new JwtMalformedException("Header not found");

        String headerBase64 = jwtBase64.substring(0, dotAfter);
        JwtClaims headerClaims = serializer.deserializeClaimsBase64(headerBase64);

        return new JwtHeader(headerClaims);
    }

    private static String[] splitTokenBase64(String jsonWebToken) throws JwtMalformedException {
        if(jsonWebToken == null) throw new IllegalArgumentException("Json Web Token must not be null");
        String[] parts = jsonWebToken.split("\\.");
        if(parts.length != 3) throw new JwtMalformedException("Json Web Token must have exactly 3 sections");
        return parts;
    }
}
