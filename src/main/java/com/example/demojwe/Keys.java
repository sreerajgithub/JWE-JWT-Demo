package com.example.demojwe;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import net.minidev.json.JSONObject;

public class Keys {
    // Key generation

    public JSONObject generateKeys() throws Exception {
        try {
            // Key generation
            KeyPairGenerator keyGenerator = null;
            try {
                keyGenerator = KeyPairGenerator.getInstance("RSA");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            keyGenerator.initialize(2048);
            KeyPair kp = keyGenerator.genKeyPair();
            JSONObject objResponse = new JSONObject();
            objResponse.put("Private Key", Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded()));
            objResponse.put("Public Key", Base64.getEncoder().encodeToString(kp.getPublic().getEncoded()));
            return objResponse;
        } catch (Exception e) {
            throw e;
        }
    }

    public RSAPrivateKey getPrivateKey(String privateKeyString) throws Exception {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyString));
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            RSAPrivateKey privKey = (RSAPrivateKey) kf.generatePrivate(keySpecPKCS8);
            return privKey;
        } catch (Exception e) {
            throw e;
        }
    }

    public RSAPublicKey getPublicKey(String publicKeyString) throws Exception {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyString));
            RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);
            return pubKey;
        } catch (Exception e) {
            throw e;
        }
    }
    
}