package dev.ysdaeth.jwt;

import java.security.Key;
import java.util.Objects;

public class Jwt {
    private final Header header;
    private final Payload payload;
    private Signature signature;

    /**
     * Constructor used by this package ONLY classes to create unsafe instance, or other reason.
     * Public access is forbidden to avoid creating unsafe tokens
     * @param header header
     * @param payload payload
     * @param signature signature
     */
    Jwt(Header header, Payload payload, Signature signature){
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
    public Jwt(Header header, Payload payload){
        this.header = Objects.requireNonNull( header);
        this.payload = Objects.requireNonNull(payload);
    }

    /**
     * Creates {@link Signature} for that instance as a field value, then
     * returns string which is full compact (serialized) JSON Web Token.
     * @param signKey key used to sign the token
     * @param jwtAlgorithm type of jwt like. RS256, HS256, etc.
     * @return JSON Web Token as a string base64 encoded with separators '.'
     */
    public String sign(Key signKey, JwtAlgorithm jwtAlgorithm) throws JwtStateException{
        if(this.signature != null) throw new JwtStateException("Jwt is already signed");

        JwtSigner signer = JwtSignerFactory.getInstance( jwtAlgorithm.name() );
        if(signer == null) throw new RuntimeException(
                "There is no such registered jwt algorithm '%s'".formatted(jwtAlgorithm.name()));

        return signer.sign(this, signKey);
    }

    /**
     * Returns mutable header instance
     * @return Jwt header instance
     */
    public Header getHeader() {
        return header;
    }

    /**
     * Returns mutable Jwt payload instance
     * and every set method will throw {@link JwtStateException}
     * @return jwt payload instance
     */
    public Payload getPayload() {
        return payload;
    }

    /**
     * Returns immutable {@link Signature} of the signed Jwt token.
     * @return Jwt signature object
     */
    public Signature getSignature() {
        return signature;
    }

    /**
     * Package private access only to avoid creating unsafe instance.
     * Signature can be assigned only once for safety reasons.
     * @param signature signature for that instance.
     */
    void setSignature(Signature signature){
        if(this.signature != null) throw new RuntimeException("JWT Signature must not be re-assigned");
        this.signature = signature;
    }

    public static Jwt parse(String serializedJwt, Key verificationKey)
            throws MalformedJwtException, SecurityException {

        Header header = JwtSigner.getUnsafeHeader(serializedJwt);
        String algorithm = header.getAlgorithm();
        return parse(serializedJwt, algorithm, verificationKey);
    }

    public static Jwt parse(String serializedJwt, KeyLocator verificationKeyLocator)
            throws MalformedJwtException, SecurityException {
        Header header = JwtSigner.getUnsafeHeader(serializedJwt);
        Key key = verificationKeyLocator.findKey( header.getKeyId() );
        String algorithm = header.getAlgorithm();
        return parse(serializedJwt, algorithm, key);
    }

    private static Jwt parse(String serializedJwt, String jwtAlgorithm, Key key)
            throws MalformedJwtException, SecurityException {
        JwtSigner signer = JwtSignerFactory.getInstance(jwtAlgorithm);
        if(signer == null){
            throw new RuntimeException(
                    "Unsupported algorithm '%s'".formatted(jwtAlgorithm));
        }
        return signer.verify(serializedJwt, key);
    }

}
