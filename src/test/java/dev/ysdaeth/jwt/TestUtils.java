package dev.ysdaeth.jwt;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.List;

public class TestUtils {


    public static SecretKey loadKey(JwtAlgorithm algorithm){
        String filename = algorithm.name() + ".key";
        List<String> content = loadFile(filename);
        String algName = content.get(0);
        return new SecretKeySpec(
                decode(content.get(1)),
                algName
        );
    }

    public static KeyPair getKeyPair(JwtAlgorithm algorithm){
        String filename = algorithm.name() + ".key";
        List<String> content = loadFile(filename);
        String keyAlg = content.get(0);
        byte[] encodedPub = decode(content.get(2));
        byte[] encodedPriv = decode(content.get(1));

        try{
            KeyFactory keyFactory = KeyFactory.getInstance(keyAlg);
            PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(encodedPriv);
            PrivateKey privateKey = keyFactory.generatePrivate(privateSpec);

            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(encodedPub);
            PublicKey pubKey = keyFactory.generatePublic(publicSpec);
            return new KeyPair(pubKey, privateKey);

        }catch (Exception e){
            throw new RuntimeException("Failed to read key file");
        }
    }

    public static String loadToken(JwtAlgorithm algorithm){
        String filename = algorithm.name() + ".token";
        List<String> content = loadFile(filename);
        return content.get(0);
    }

    public static Jwt createUnsignedJwt(JwtAlgorithm algorithm){
        Instant instant = ZonedDateTime.of(
                2018, 1, 18,
                2, 30, 22,
                0,
                ZoneId.of("Europe/Warsaw")
        ).toInstant();

        JwtHeader header = new JwtHeader();
        header.setAlgorithm(algorithm.name());
        header.setType("JWT");

        JwtPayload payload = new JwtPayload();
        payload.setSubject("1234567890");
        payload.add("admin",true);
        payload.setIssuedAt(instant);
        return new Jwt(header, payload);
    }

    private static byte[] decode(String base64){
        return Base64.getDecoder().decode(base64);
    }

    private static List<String> loadFile(String filename)  {
        try{
            Path path = Path.of("src","test", "resources", "jwt", filename);
            return Files.readAllLines(path).stream().map(String::trim).toList();
        } catch (Exception e) {
            throw new RuntimeException("");
        }
    }
}
