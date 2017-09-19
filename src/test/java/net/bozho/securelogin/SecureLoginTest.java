package net.bozho.securelogin;

import org.junit.Assert;
import org.junit.Test;

import java.time.LocalDateTime;
import java.util.Collections;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

public class SecureLoginTest {

    private static final String DOMAIN = "https://cobased.com";

    @Test
    public void buildTest() {
        String token = "https://cobased.com%2Chttps://cobased.com%2C%2C1498731060," + 
                "E5faDp1F3F4AGN2z5NgwZ/e0WB+ukZO3eMRWvTTZc4erts8mMzSy+CxGdz3OW1Xff8p6m" + 
                "DAPfnSK0QqSAAHmAA==%2CcIZjUTqMWYgzYGrsYEHptNiaaLapWiqgPPsG1PI/Rsw=," + 
                "kdbjcc08YBKWdCY56lQJIi92wcGOW+KcMvbSgHN6WbU=%2C1OVh/+xHRCaebQ9Lz6k" + 
                "OTkTRrVm1xgvxGthABCwCQ8k=,homakov@gmail.com";
        
        try {
            SecureLogin login = SecureLogin.verify(token,
                    Options.create(DOMAIN).setPerformHmacCheck(true).setPerformExpirationCheck(false));
            
            assertThat(login.getClient(), equalTo(DOMAIN));
            assertThat(login.getProvider(), equalTo(DOMAIN));
            assertThat(login.getScope(), equalTo(Collections.emptyMap()));
            assertThat(login.getExpiresAt(), equalTo(LocalDateTime.of(2017, 6, 29, 10, 11)));
        } catch (SecureLoginVerificationException e) {
            Assert.fail("Unexpected failure: " + e.getFailure());
        }
    }
}
