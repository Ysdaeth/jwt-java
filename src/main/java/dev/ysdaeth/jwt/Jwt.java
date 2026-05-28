package dev.ysdaeth.jwt;

import java.security.Key;

public class Jwt {
    private static final JwtSerializer serializer = new JwtSerializer();

    private final Header header;
    private final Payload payload;
    private Signature signature;

    /**
     * Constructor used by this package to create, check and manage this instance.
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
     * a method {@link this#sign(Key, JwtType)} creates Signature field and returns compact JWT.
     * @param header JWT Header
     * @param payload JWT Payload
     */
    public Jwt(Header header, Payload payload){
        this.header = header;
        this.payload = payload;
    }

    /**
     * Creates {@link Signature} for that jwt token as a field value, then
     * returns string which is full compact JSON Web Token.
     * @param signKey key used to sign the token
     * @param jwtType type of jwt like. RS256, HS256, etc.
     * @return JSON Web Token as a string base64 encoded with separators '.'
     */
    public String sign(Key signKey, JwtType jwtType){
        if(this.signature != null) throw new MalformedJwtException("Jwt is already signed");
        JwtSigner signer = JwtSignerFactory.getInstance(jwtType);

        header.setBase64( serializer.serialize(header) );
        payload.setBase64( serializer.serialize(payload) );

        this.signature = signer.sign(header, payload, signKey);
        return serializer.concatSerialized(header, payload, signature);
    }

    public Header getHeader() {
        return header;
    }

    /**
     * Parses Jwt and returns {@link Header}, which is unsafe object.
     * @param jwt compact jwt token.
     * @return Jwt header
     */
    public static Header parseUnsafeHeader(String jwt){
        Jwt parsedJwt = parseJwt(jwt);
        return parsedJwt.header;
    }

    /**
     * Returns verified Jwt {@link Payload}
     * @return jwt payload object
     */
    public Payload getPayload() {
        return payload;
    }

    /**
     * Returns {@link Signature} of the signed Jwt token.
     * @return Jwt signature object
     */
    public Signature getSignature() {
        return signature;
    }

    private static Jwt parseJwt(String jwt) throws MalformedJwtException {
        try{
            return serializer.deserialize(jwt);
        }catch (JwtStateException e){
            throw new MalformedJwtException("Malformed Jwt token." + e.getMessage(), e);
        }
    }

    public static Jwt verify(String jwt, Key verificationKey) throws MalformedJwtException {
        Jwt parsedJwt = parseJwt(jwt);
        JwtType jwtType;

        try{
            jwtType = JwtType.valueOf( parsedJwt.header.getType() );
        }catch (IllegalArgumentException e){
            throw new MalformedJwtException("Malformed Jwt token." + e.getMessage(), e);
        }

        JwtSigner signer = JwtSignerFactory.getInstance(jwtType);
        boolean isVerified = signer.verify(parsedJwt, verificationKey);
        if(!isVerified) throw new SecurityException("Jwt signature does not match content.");

        return new Jwt(parsedJwt.header, parsedJwt.payload, parsedJwt.signature);
    }


}
