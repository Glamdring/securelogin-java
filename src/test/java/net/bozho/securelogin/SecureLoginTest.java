package net.bozho.securelogin;

import org.junit.Test;

public class SecureLoginTest {

    @Test
    public void buildTest() {
        String token = "https://foo.com%2Chttps://bar.com%2C%2C1505769356,"
                + "YKKX4ryRMWsYhEZAyghVmHzjTJWvlJClgj43G8lmED83CbofFN2FuUQRo3nrOMcCAfSS3jUshfAlqD4WVoPQDw==,"
                + "/Pw4Ug0iPzwplLq16ehYGmiauy1YYRUk6CAcVIgX9UE=,"
                + "wqgjDhAu SKYgsXiqp2o2py1k6NSHA uqZeBhI7vKTE=,"
                + "0p9skGbu1Fnr4/Nsgik fwfqiMVYVcUywdTFejV8CvU=,"
                + "someemail@gmail.com";
        
        SecureLogin.build(token);
    }
}
