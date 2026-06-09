package dev.ysdaeth.jwt;

import dev.ysdaeth.jwt.exception.*;

import java.security.Key;
import java.util.Objects;

public class Jwt {
    private final JwtHeader header;
    private final JwtPayload payload;
    private JwtSignature signature;

    /**
     * Constructor used by this package ONLY classes to create unsafe instance, or other reason.
     * Public access is forbidden to avoid creating unsafe tokens
     * @param header header
     * @param payload payload
     * @param signature signature
     */
    Jwt(JwtHeader header, JwtPayload payload, JwtSignature signature){
        this.header = header;
        this.payload = payload;
        this.signature = signature;
    }

    /**
     * Creates object of the JSON Web Token without signature. After constructing,
     * a method {@link this#sign(Key, JwtAlgorithm)} creates Signature field and returns compact JWT.
     * @param header JWT Header
     * @param payload JWT Payload
     */
    public Jwt(JwtHeader header, JwtPayload payload){
        this.header = Objects.requireNonNull( header);
        this.payload = Objects.requireNonNull(payload);
    }

    /**
     * Creates {@link JwtSignature} for that instance as a field value, then
     * returns string which is full compact (serialized) JSON Web Token.
     * @param signKey key used to sign the token
     * @param jwtAlgorithm type of jwt like. RS256, HS256, etc.
     * @return JSON Web Token as a string base64 encoded with separators '.'
     */
    public String sign(Key signKey, JwtAlgorithm jwtAlgorithm) throws JwtStateException {
        if(this.signature != null) throw new JwtStateException("Jwt is already signed");
        JwtSigner signer = JwtSignerFactory.getInstance(jwtAlgorithm);
        String jwt = signer.sign(this, signKey);
        lock();
        return jwt;
    }

    /**
     * Returns mutable (when unsigned) or immutable (when signed) instance.
     * Immutable instance will throw exception when claims are modified
     * @return Jwt header instance
     */
    public JwtHeader getHeader() {
        return header;
    }

    /**
     * Returns mutable (when unsigned) or immutable (when signed) instance.
     * Immutable instance will throw exception when claims are modified
     * @return jwt payload instance
     */
    public JwtPayload getPayload() {
        return payload;
    }

    /**
     * Returns immutable {@link JwtSignature} of the signed Jwt token or null when not signed.
     * @return Jwt signature object
     */
    public JwtSignature getSignature() {
        return signature;
    }

    /**
     * Package private access only to avoid creating unsafe instance.
     * Signature can be assigned only once for safety reasons.
     * @param signature signature for that instance.
     */
    void setSignature(JwtSignature signature){
        if(this.signature != null) throw new RuntimeException("JWT Signature must not be re-assigned");
        this.signature = signature;
    }

    /**
     * Lock the claims to make them immutable
     */
    private void lock(){
        payload.lock();
        header.lock();
    }

    /**
     * Parse string format of JSON Web Token to object representation. Returned Jwt instance is always valid
     * and not expired. Parsed JWT instance throws exception when claims are modified.
     * @param jwt JSON Web Token base64 encoded
     * @param verificationKey Key to verify JWT signature
     * @return verified and immutable JWT instance
     * @throws JwtMalformedException when jwt is malformed, bytes encoding is incorrect, etc.
     * @throws JwtSignatureException when signature does not match.
     * @throws JwtExpiredException when jwt is expired
     * @throws JwtUnsupportedException when algorithm or type is not supported
     */
    public static Jwt parse(String jwt, Key verificationKey)
            throws JwtMalformedException, JwtSignatureException, JwtExpiredException, JwtUnsupportedException {

        JwtHeader header = JwtSigner.getUnsafeHeader(jwt);
        JwtAlgorithm algorithm = extractAlgorithm(header);
        return parse(jwt, algorithm, verificationKey);
    }

    /**
     * Parse string format of JSON Web Token to object representation. Returned Jwt instance is always valid
     * and not expired. Parsed JWT instance throws exception when claims are modified.
     * @param jwt JSON Web Token base64 encoded
     * @param verificationKeyLocator Functional interface that provides key to verify signature
     * @return verified and immutable JWT instance
     * @throws JwtMalformedException when jwt is malformed, bytes encoding is incorrect, etc.
     * @throws JwtSignatureException when signature does not match.
     * @throws JwtExpiredException when jwt is expired
     * @throws JwtUnsupportedException when algorithm or type is not supported
     */
    public static Jwt parse(String jwt, KeyLocator verificationKeyLocator)
            throws JwtMalformedException, JwtSignatureException, JwtExpiredException, JwtUnsupportedException {
        JwtHeader unsafeHeader = JwtSigner.getUnsafeHeader(jwt);
        Key key = verificationKeyLocator.findKey( unsafeHeader );
        JwtAlgorithm algorithm = extractAlgorithm(unsafeHeader);
        return parse(jwt, algorithm, key);
    }

    /**
     * Parse string format of JSON Web Token to object representation. Returned Jwt instance is always valid
     * and not expired. Parsed JWT instance throws exception when claims are modified.
     * @param jwt JSON Web Token base64 encoded
     * @param key key to verify signature
     * @return verified and immutable JWT instance
     * @throws JwtMalformedException when jwt is malformed, bytes encoding is incorrect, etc.
     * @throws JwtSignatureException when signature does not match.
     * @throws JwtExpiredException when jwt is expired
     * @throws JwtUnsupportedException when algorithm or type is not supported
     */
    private static Jwt parse(String jwt, JwtAlgorithm jwtAlgorithm, Key key)
            throws JwtMalformedException, JwtSignatureException, JwtExpiredException, JwtUnsupportedException {
        JwtSigner signer = JwtSignerFactory.getInstance(jwtAlgorithm);
        Jwt jwtDeserialized = signer.verify(jwt, key);
        jwtDeserialized.lock();
        return jwtDeserialized;
    }

    private static JwtAlgorithm extractAlgorithm(JwtHeader header) throws JwtUnsupportedException{
        String algorithmName = header.getAlgorithm();
        try{
            return JwtAlgorithm.valueOf(algorithmName);
        }catch (Exception e){
            throw new JwtUnsupportedException("Unsupported JWT algorithm '%s' ".formatted(algorithmName));
        }
    }

    @Override
    public boolean equals(Object obj) {
        if(obj instanceof Jwt other){
            return header.equals(other.header)
                    && payload.equals(other.payload) &&
                    signature.equals(other.signature);
        }
        return false;
    }
}
