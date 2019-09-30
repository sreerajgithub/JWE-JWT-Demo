package com.example.demojwe;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import net.minidev.json.JSONObject;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @RequestMapping(value = "/v1/keys")
    @ResponseBody
    public JSONObject generateKeys() {
        Keys keys = new Keys();
        JSONObject keyResponse = null;
        try {
            keyResponse = keys.generateKeys();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return keyResponse;
    }

    @GetMapping(value = "/v1/jwe/encode")
    public Map<String, String> jweEncode() throws Exception {
        String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgI9ZfpORWxlTIz3EfxBJFdT+CmXfkKcQBbKQUmn3Sa5cKtLD3dBZ1zi4/1ak8pEOuNGVbfcm4XC+NoHtLgVkbqKPcvyW+Rub3lwl68vl7uKMU1vNU230kf36r0sR3SmeC+3a38YQW48nsv3yB/TN+rb3Rt40Gf5xfp6l9FltLYYjRjMT2hOiCeTa/kPbnjCRlSWT08ZKJV4B3f9DRpn6Hcp42ai6FYkSwTXAtAGT1Gs746iianHqIR/BAeOaop+vCBFd8alaibQ6Tx87+gy8EviZ53tKvmiAEt335II+uwWny0Qa9CLiQoPQx7QAwH1NlzoRFb/64NftCDuQJHrBDQIDAQAB";
        // RSA Key class
        Keys keys = new Keys();
        JWEObject jweObject;

        Timestamp timestampISS = new Timestamp(System.currentTimeMillis());
        Timestamp timestampEXP = new Timestamp(System.currentTimeMillis() + 30000);

        // Create an empty claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                // Add claims to the claims set
                .issuer("Amdocs-CRM").subject("LaunchPad").audience("FidoOneView").issueTime(timestampISS)
                .expirationTime(timestampEXP).jwtID("63a270c8-f180-43c8-b227-cffb8511c683")
                .claim("interactionId", "I2000000289").claim("accountNumber", "219608023")
                .claim("contactId", "CO1000000050").claim("agentRoles",
                        "System Administrator,CSR,Authorization Administrator,BT System Admin,BT User,R252")
                .build();

        // Print JSON representation of claims set
        System.out.println(claimsSet.toJSONObject());

        // Request that JWE is created RSA-OAEP-256 and 128-bit AES/GCM
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);

        // Create the JWT object (not yet encrypted)
        EncryptedJWT jwt = new EncryptedJWT(header, claimsSet);

        // Create an encrypter with the public RSA key
        RSAEncrypter encrypter = new RSAEncrypter(keys.getPublicKey(publicKey));

        // Do the encryption
        try {
            // This library will generate a random content encryption key during this step
            // Other libararies may require that both the RSA key and the CEK are provided
            jwt.encrypt(encrypter);
        } catch (JOSEException e) {
            e.printStackTrace();
        }

        // Serialise to JWT compact form
        String jwtString = jwt.serialize();

        HashMap<String, String> map = new HashMap<>();
        map.put("Encoded", jwtString);

        return map;
    }

    @GetMapping(value = "/v1/jwe/decode")
    public net.minidev.json.JSONObject jweDecode() throws Exception {
        String privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCAj1l+k5FbGVMjPcR/EEkV1P4KZd+QpxAFspBSafdJrlwq0sPd0FnXOLj/VqTykQ640ZVt9ybhcL42ge0uBWRuoo9y/Jb5G5veXCXry+Xu4oxTW81TbfSR/fqvSxHdKZ4L7drfxhBbjyey/fIH9M36tvdG3jQZ/nF+nqX0WW0thiNGMxPaE6IJ5Nr+Q9ueMJGVJZPTxkolXgHd/0NGmfodynjZqLoViRLBNcC0AZPUazvjqKJqceohH8EB45qin68IEV3xqVqJtDpPHzv6DLwS+Jnne0q+aIAS3ffkgj67BafLRBr0IuJCg9DHtADAfU2XOhEVv/rg1+0IO5AkesENAgMBAAECggEAf9CFdI+4Uy8hdgciBgYl83u4OpRAKmu+RTvbuuQ5hFrCrZywOSa9O3nci5gUFEndrihI/XRchoR1yHFyYm/gAxLBtdulKfOmCvPoi79DUjaQtwutXsYSAtfU1VS4ZP7McCXBlvsvJih0msNZT0m3RA2GWUHv4OwU4INQkVgbcMbQJSJonvbxanv00HzrcOS98ET6YZo/ODKzXqKS+5DB6C0LBJQzbM1aoL+CCn6m7GtynvzM8O7DHQWF1rvReicFkxE4DIdCnefD+8jo9YDuZtPUWCk6RMIda7eZCRmr0TU8Q6OO54K4rJBT/F/7jBErFbdsbJm7y3ZfTPPV7Iya4QKBgQD8yTxlEqYEPy2qu7O4bBckjbqDo/t7j6Vhv+spmQqGFGHqgYdXx4PSRCWcJZWrnt9CjPeuLZ9gR2CtHSKmGo9s8kkGpvKPC9pdilKn9CuWH5rzNwfeuTKapCyfU8wHGtYqiSg40s8X/GNzTOeih1mL2wSnrRJGtFz3YCbGAh57OQKBgQCCMcjUI10pDHQjsoUnAOxwmLA26Ystj+MRYm5ZrCmk1rmSFw3SVuGXQ22uP0QGv7Adzj6G5zkbp9KH1SQvOf0sGiYC2fSMxdULv81JU+G86xwynZ33k9WpyI1cieVrlz0xEnF+VIHvZ9A8TPmPNJtUm8PfLQEzZKDrFx0Idj/wdQKBgAcgxYs0E2pbPbZqxI6WvbBSLsg3f4fkbQ1sk/0AS8OsH3a1YFOhVJ5BPa5BgQ7t0+3Ue8d1keDtIlS/VZLJfPHdgyGk44IVG3s3w0zpHbGGAqCJFLe7ESo7Jub3PfGVWCSq6W9wwlYyz7sYmA+FMYk4C9GOl81WmKiBFZbPyHxBAoGACCw74SU/Kd6AQ+Vm+mXScdcD6M6MUBXiOSsmpjZqftCD4anU0kll6+rtrayHBq1tztEtl6ZYLWZBjwlQNi67t9MEY9Vuxo98qjomFt5PI17W7E58phf/p6LRTOfTIQfjbXss6LNBXNf1eHOUjurMfWkxyIa4tpMwjtFqnyddKCkCgYEAoLP28eiLtYOJxETZdB4J5/eciCBfdnkMPN+A7B1e/QB2k1wygp7cl4d96pkWAPnFxyq2tuBalslisuOWoMHjXsWfp9rGqTXznNNuvSvT/kXVBWl3LXTVAAseITdS3yWx+Jgeup0JGx/MOkJl06fTOECOyUOp9dT+WEG2GRLgn5E=";
        String jwtString = "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.GbtxQOp0YfmLWu_5HWJ06mtqYodRRNVWEMYXskDPvSjlP25neq9RpSkKIezCbmHqkd5wRLVmldHjQmQFsIjKAk_RJHaozcGx5RTYbWgKykbi-mYh1H43IFQsJND8f7NxfWXHs7EzcfMx9KzamzHcP95XT8lYVMNs5PoKLVxsww52pLQtLRfN09ckq1W51pldZY9I09PH7llDPpAbi6FjfuVTrWtrMIrtv2H-eYFBG9QQNrCNFCx3xs2jh_MvDfR-DI3r_qGeC74cBcQzyvWUHnS_NsLyV8tN5kzvqwxMknKlStEpCifSHFzAa27UVuhVf8cb9BtdEeyh7VcpQVQ_Ng.Q99V1kA8Yr3kRons.9A28sv6nZ2W1zWguwwA6WQgeUkSEtduAomIwNeHag58frL1nW4dVJ-SoFGkX73-MUMeqXcIFOkvlXONo9rcSRXcDyvK0-iPRpSEt9PHNNd2ccw5atWhbMNt3QdoAiZ3OvEcSig7wWyegBjpA4zAtuOaBjfWV0pQnkV4aoMqYbAD0TIBBiQ5qvAuhMF4T_PQA2rgC83mFGe2W8KEccpMQxF1CJEp8EtyiT7KezaISRcE-HKC9C9q2IUGy9Pr-W60Lzz_7CvCwWibJn6kGo0o0-iYotUUEvGufg6GTlwNMLOAqCyrHTk_ggLJpyEAK6F6CKRTs2mAQIk5Lx55QwcOSsnTYVsgUCsGrg3hSSl_TNyfc_DKAc_xoP0hcf39Eo2g5o60y-q7drAxftobcprckVQhOVTjkJhtm0t0MuJNCAg.yQ6OJT5SAjmuRBZeVHYzpw";
        // RSA Key class
        Keys keys = new Keys();

        // Parse the JWT from serialized string format
        EncryptedJWT jwt = EncryptedJWT.parse(jwtString);

        // Verify the JWT uses safe algorithms
        if (!jwt.getHeader().getAlgorithm().equals(JWEAlgorithm.RSA_OAEP_256))
            throw new Exception("Invalid 'alg' header, only RSA-OAEP-256 is allowed.");

        if (!jwt.getHeader().getEncryptionMethod().equals(EncryptionMethod.A256GCM))
            throw new Exception("Invalid 'enc' header, only A128GCM is allowed.");

        // Create a decrypter with the specified private RSA key
        RSADecrypter decrypter = new RSADecrypter(keys.getPrivateKey(privateKey));

        // Decrypt JWT
        jwt.decrypt(decrypter);

        return jwt.getPayload().toJSONObject();

    }
}