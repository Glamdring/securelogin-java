package net.bozho.securelogin;

public class SecureLogin {

    // spec https://github.com/sakurity/securelogin-spec/blob/master/index.md
    public static SecureLogin build(String token) {
        String[] args = token.split(",");
        String message = args[0];
        String signature = args[1];
        String hmacSignature = args[2];
        String publicKey = args[3];
        String secret = args[4];
        
        return new SecureLogin();
    }
}
