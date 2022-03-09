package com.example.thandbag.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.thandbag.security.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtTokenUtils {
    public static final int SEC = 1;
    public static final int MINUTE = 60 * SEC;
    public static final int HOUR = 60 * MINUTE;
    public static final int DAY = 24 * HOUR;
    //private static final int JWT_TOKEN_VALID_SEC = 3 * DAY; // JWT 토큰의 유효기간: 3일 (단위: seconds)
    //private static final int JWT_TOKEN_VALID_MILLI_SEC = JWT_TOKEN_VALID_SEC * 1000; // JWT 토큰의 유효기간: 3일 (단위: milliseconds)

    public static final String CLAIM_EXPIRED_DATE = "EXPIRED_DATE";
    public static final String CLAIM_USER_NAME = "USER_NAME";

    @Autowired
    private Environment environment;

    public String generateJwtToken(UserDetailsImpl userDetails, int expiration) {
        String token = null;
        System.out.println("jwtSecret: " + environment.getProperty("jwt.secret"));
        try {
            token = JWT.create()
                    .withIssuer("thandbag")
                    .withClaim(CLAIM_USER_NAME, userDetails.getUsername())
                    /* 토큰 만료 일시 = 현재 시간 + 토큰 유효기간) */
                    .withClaim(CLAIM_EXPIRED_DATE,
                            new Date(System.currentTimeMillis() +
                                    expiration * 1000))
                    .sign(generateAlgorithm());
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return token;
    }

    private Algorithm generateAlgorithm() {
        //System.out.println("jwtSecret: " + environment.getProperty("jwt.secret"));
        return Algorithm.HMAC256(environment.getProperty("jwt.secret"));
    }
}