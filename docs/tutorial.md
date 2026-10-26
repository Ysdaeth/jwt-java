# How to use
Library is really simple to use, methods names are created to be self-explanatory, 
so this tutorial will not be that much detailed. it supports nested Collections and Maps.

> [!WARNING]
> Collections and Maps are immutable but state of mutable objects can be changed, so it is recommended
to use `record` or `immutable class`

- [How to install package](#how-to-install-package)
- [Claims](#create-claims)
  - [Header](#create-jwt-header)
  - [Payload](#create-jwt-payload)
- [Create token](#create-token)
- [Parse token](#parse-token)
- [Parse token with KeyLocator](#parse-token-with-keylocator)


## How to install package
Package is available to download with GitHub Packages,  **NOT** with **Maven Repository**, but will be soon.  
There are 2 ways to install it with maven.

### Download with GitHub packages
Add to `.m2/settings.xml`:
```xml
<repository>
    <id>gh-ys-jwt-java</id> <!-- Or any other id you like-->
    <url>https://maven.pkg.github.com/Ysdaeth/jwt-java</url>
</repository>
```

### Or clone repository and install locally
```shell
git clone https://github.com/Ysdaeth/jwt-java.git
cd jwt-java
sudo mvn clean install
```

### Then add dependency to project
```xml
<dependency>
    <groupId>dev.ysdaeth.jwt</groupId>
    <artifactId>jwt-java</artifactId>
    <version>x.y.z</version>
</dependency>
```

---

## Create claims

### Create JWT Header
Header contains most common fields, but you can add own custom attribute. 
When signing JWT header algorithm is set automatically, so you don't need to specify it.
Header claims are immutable **ONLY** when signed.

```java
JwtHeader header = new JwtHeader();
header.setKeyId("my-key");
header.add("key","value");
```

### Create JWT Payload
Payload claims are immutable **ONLY** when signed.

```java
JwtPayload payload = new JwtPayload();
payload.setSubject("you");
payload.setExpiresAt(expiresAt);
payload.add("iLikeCats",true);
```

## Create Token
First Jwt instance must be created. It contains JwtHeader and JwtPayload objects.
Once signature is created, it cannot be created once again from the same instance.
Furthermore, changing header or payload claims will throw JwtStateException.

```java
Jwt jwt = new Jwt(header, payload);
JwtAlgorithm algorithm = JwtAlgorithm.HS256;
Key signKey; // generate key
String token = jwt.sign(signKey, algorithm);
```

## Parse token
When key does not match the signature, the SecurityException is thrown. 
Also, it is not possible to change claims of the parsed Jwt instance, doing so will throw an exception.

```java
String jsonWebToken = ...;
Key key = ...;
 
Jwt jwt = Jwt.parse(jsonWebToken, key); // if key is invalid throws SecurityException

JwtPayload payload = jwt.getPayload();
JwtHeader header = jwt.getHeader();

String subject = payload.getSubject();
```

## Parse token with KeyLocator
KeyLocator is a **functional interface**, it is used to supply the unsafe header (not verified) to access required fields 
like key id or public key location. 

```java
class MyKeyLocator implements KeyLocator {
    private Key key = ...;

    public Key findKey(JwtHeader unsafeHeader) {
        String keyId = unsafeHeader.getKeyId();
        if("keyId".equals(keyId)) return key;
        return null;
    }
}
```

Now lets use our KeyLocator to verify and parse Jwt.

```java
MyKeyLocator myKeyLocator = new MyKeyLocator();
String jsonWebToken = ...;
Jwt jwt = Jwt.parse(jsonWebToken, myKeyLocator); //or lambda expression
```
