package net.bozho.securelogin;

import org.junit.Assert;
import org.junit.Test;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.function.Consumer;
import java.util.function.Function;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static java.util.function.Function.identity;

public class SecureLoginTest {

    private static final String DOMAIN = "https://cobased.com";

    private String token = "https://cobased.com%2Chttps://cobased.com%2C%2C1498731060," + 
            "E5faDp1F3F4AGN2z5NgwZ/e0WB+ukZO3eMRWvTTZc4erts8mMzSy+CxGdz3OW1Xff8p6m" + 
            "DAPfnSK0QqSAAHmAA==%2CcIZjUTqMWYgzYGrsYEHptNiaaLapWiqgPPsG1PI/Rsw=," + 
            "kdbjcc08YBKWdCY56lQJIi92wcGOW+KcMvbSgHN6WbU=%2C1OVh/+xHRCaebQ9Lz6k" + 
            "OTkTRrVm1xgvxGthABCwCQ8k=,homakov@gmail.com";
    
    @Test
    public void buildTest() {
        try {
            SecureLogin login = SecureLogin.verify(token,
                    Options.create(DOMAIN).setPerformHmacCheck(true).setPerformExpirationCheck(false));
            
            assertThat(login.getClient(), equalTo(DOMAIN));
            assertThat(login.getProvider(), equalTo(DOMAIN));
            assertThat(login.getScope(), equalTo(Collections.emptyMap()));
            assertThat(login.getExpiresAt(), equalTo(LocalDateTime.of(2017, 6, 29, 10, 11)));
            assertThat(login.getRawPublicKey(), equalTo("kdbjcc08YBKWdCY56lQJIi92wcGOW+KcMvbSgHN6WbU="));
        } catch (SecureLoginVerificationException e) {
            Assert.fail("Unexpected failure: " + e.getFailure());
        }
    }
    
    @Test
    public void invalidOriginsTest() {
        failureTest(identity(), opts -> opts.setOrigins(Collections.singleton("https://fakedomain.com")),
                SecureLoginVerificationFailure.INVALID_PROVIDER);
    }
    
    @Test
    public void invalidSignatureTest() {
        failureTest(token -> token.replace("E5faDp", "111111"), opts -> {}, SecureLoginVerificationFailure.INVALID_SIGNATURE);
    }
    
    @Test
    public void invalidHmacTest() {
        failureTest(token -> token.replace("OTkT", "1111"), opts -> {}, SecureLoginVerificationFailure.INVALID_HMAC);
    }
    
    @Test
    public void expiredTest() {
        failureTest(identity(), opts -> opts.setPerformExpirationCheck(true), SecureLoginVerificationFailure.EXPIRED_TOKEN);
    }
    
    public void failureTest(Function<String, String> modifyToken, Consumer<Options> modifyOptions, SecureLoginVerificationFailure expected) {
        try {
            String modifiedToken = modifyToken.apply(token);
            Options options = Options.create(DOMAIN).setPerformHmacCheck(true).setPerformExpirationCheck(false);
            modifyOptions.accept(options);
            SecureLogin.verify(modifiedToken, options);
            Assert.fail("Verification should have failed");
        } catch (SecureLoginVerificationException e) {
            assertThat(e.getFailure(), equalTo(expected));
        }
    }
}
