package dev.ysdaeth.jwt;

import java.security.Key;

public class Jwt {
    private static final JwtSerializer serializer = new JwtSerializer();

    private boolean isVerified = false;
    private Header header;
    private Payload payload;
    private Signature signature;

    private String token;

    public Jwt(Header header, Payload payload, Signature signature){
        this.header = header;
        this.payload = payload;
        this.signature = signature;
    }

    public Jwt(String jwt){
        Jwt parsedJwt;
        try{
            parsedJwt = serializer.deserialize(jwt);
        }catch (MalformedTokenException e){
            throw new JwtStateException("Malformed Jwt token." + e.getMessage(), e);
        }

        this(parsedJwt.header, parsedJwt.payload, parsedJwt.signature);
    }

    public String sign(Key signKey, JwtType jwtType){
        if(this.signature != null) throw new JwtStateException("Jwt is already signed");
        JwtSigner signer = JwtSignerFactory.getInstance(jwtType);
        this.signature = signer.createSignature(header, payload, signKey);
        return serializer.serialize(this);
    }

    boolean verify(Key verificationKey){
        JwtType type = JwtType.valueOf(header.getType());
        JwtSigner signer = JwtSignerFactory.getInstance(type);
        isVerified = signer.verify(header, payload, signature, verificationKey);
        return isVerified;
    }

    public Header getHeader() {
        return header;
    }

    public Payload getPayload() {
        if(isVerified) return payload;
        throw new JwtStateException("Jwt is not verified, or method 'verify()' was not called");
    }

    public Signature getSignature() {
        return signature;
    }

}
