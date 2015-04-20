package com.example.powertest;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.io.IOUtils;

import android.util.Base64;

public class RSACipher implements com.example.powertest.Cipher {
	private final String transformation = "RSA/ECB/PKCS1Padding";
    private final String encoding = "UTF-8";
    
    private PublicKey publicKey;
    private PrivateKey privateKey;
    
    private Cipher cipher;
    
    public RSACipher(PublicKey publicKey, PrivateKey privateKey) throws GeneralSecurityException{
    	cipher = Cipher.getInstance(transformation);
        
    	this.privateKey = privateKey;
    	this.publicKey = publicKey;
    }
    
    public PublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}
	
	public void setPublicKey(String publicKeyPath) throws IOException, GeneralSecurityException{
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(IOUtils.toByteArray(new FileInputStream(publicKeyPath)));
    	publicKey = KeyFactory.getInstance("RSA").generatePublic(x509EncodedKeySpec);
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}
	
	public void setPrivateKey(String privateKeyPath) throws IOException, GeneralSecurityException{
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(IOUtils.toByteArray(new FileInputStream(privateKeyPath)));
    	privateKey = KeyFactory.getInstance("RSA").generatePrivate(pkcs8EncodedKeySpec);
	}

	public RSACipher(String publicKeyPath, String privateKeyPath) throws IOException, GeneralSecurityException{
		cipher = Cipher.getInstance(transformation);
    	setPublicKey(publicKeyPath);
    	setPrivateKey(privateKeyPath);
    }
    
	@Override
	public BigInteger encrypt(BigInteger raw) throws IOException, GeneralSecurityException  {
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return new BigInteger(cipher.doFinal(raw.toByteArray()));
	}

	@Override
	public BigInteger decrypt(BigInteger encrypted) throws IOException, GeneralSecurityException  {
		cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new BigInteger(cipher.doFinal(encrypted.toByteArray()));

	}

}
