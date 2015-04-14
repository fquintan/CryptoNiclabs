package com.example.powertest;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.apache.commons.io.IOUtils;

import android.util.Base64;

public class RSACipher {
	
    
    public String encrypt(String rawText, String publicKeyPath, String transformation, String encoding)
            throws IOException, GeneralSecurityException {
        
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(IOUtils.toByteArray(new FileInputStream(publicKeyPath)));

        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, KeyFactory.getInstance("RSA").generatePublic(x509EncodedKeySpec));

       return Base64.encodeToString(cipher.doFinal(rawText.getBytes(encoding)), Base64.DEFAULT);
    }
    
    public String encrypt(String rawText, PublicKey publicKey, String transformation, String encoding)
            throws IOException, GeneralSecurityException {

        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return Base64.encodeToString(cipher.doFinal(rawText.getBytes(encoding)), Base64.DEFAULT);
    }

    public String decrypt(String cipherText, String privateKeyPath, String transformation, String encoding)
            throws IOException, GeneralSecurityException {

        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(IOUtils.toByteArray(new FileInputStream(privateKeyPath)));

        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, KeyFactory.getInstance("RSA").generatePrivate(pkcs8EncodedKeySpec));

        
        return new String(cipher.doFinal(Base64.decode(cipherText, Base64.DEFAULT)), encoding);
    }
    
    public String decrypt(String cipherText, PrivateKey privateKey, String transformation, String encoding)
            throws IOException, GeneralSecurityException {

        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(cipher.doFinal(Base64.decode(cipherText, Base64.DEFAULT)), encoding);
    }

}
