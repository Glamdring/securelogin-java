# securelogin-java
Java implementation of [SecureLogin.pw verification](https://github.com/sakurity/securelogin-spec/blob/master/index.md)

Usage:

```
String token = ... ; // obtain token from request
SecureLogin login = SecureLogin.verify(token, Options.create(ALLOWED_ORIGIN_DOMAINS));
String publicKey = login.getRawPublicKey();
// use public key to lookup the user in the database
```

Maven dependency:

```
<dependencey>
    <groupId>net.bozho.securelogin</groupId>
    <artifactId>securelogin-java</artifactId>
    <version>0.0.1</version>
</dependency>
```