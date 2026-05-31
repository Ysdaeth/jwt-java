import dev.ysdaeth.jwt.*;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.time.Instant;

public class Example {

    void runExample() throws Exception{
        Key key = MyKeyLocator.key;

        Header header = new Header();
        header.setKeyId("keyId");
        header.add("customHeader","value");

        Payload payload = new Payload();
        payload.setExpiresAt(Instant.now().plusSeconds(300));
        payload.setIssuer("Ysdaeth");
        payload.setSubject("You");
        payload.add("role","DEVELOPER");
        payload.add("bans", 0);
        payload.add("isBanned", false);

        Jwt jwt = new Jwt(header, payload);
        String jsonWebToken = jwt.sign(key, JwtAlgorithm.HS256);

        System.out.println("=== TOKEN ===");
        System.out.println(jsonWebToken);
        System.out.println("=== TOKEN ===");

        try{
            jwt.getPayload().add("role","ADMIN");
        }catch (JwtStateException e){
            System.out.println(
                    "You must not modify jwt claims, when it's already signed. " + e.getMessage());
        }

        Jwt parsedJwt = Jwt.parse(jsonWebToken,key);
        Payload parsedPayload = parsedJwt.getPayload();
        String subject = parsedPayload.getSubject();
        System.out.println("Hello, " + subject);

        Jwt parsedWithKeyLocator = Jwt.parse(jsonWebToken, new MyKeyLocator());
        String subject2 = parsedWithKeyLocator.getPayload().getSubject();

        System.out.println("Hello, " + subject2 +". Key locator works!");
    }

    private static class MyKeyLocator implements KeyLocator {
        public static Key key = generateKey();

        @Override
        public Key findKey(String keyId) {
            if("keyId".equals(keyId)) return key;
            return null;
        }

        static Key generateKey(){
            byte[] keyBytes = new byte[32];
            new SecureRandom().nextBytes(keyBytes);
            return new SecretKeySpec(keyBytes,"HmacSHA256");
        }

    }
}
