package com.example.powertest;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import android.util.Base64;

/**
 * Created by felipe on 4/13/15.
 */
public class AESCipher implements com.example.powertest.Cipher{

    private Cipher cipher;
    private int passwordLength;
    private int saltLength;
    private int initializationVectorSeedLength;
    
    private int hashIterations;
    private KeyLength keyLength;

    private SecretKey secretKey;

    
    public AESCipher()
            throws GeneralSecurityException{
        this(16, 16, 16, 10000, KeyLength.TWO_FIFTY_SIX);
    }

    public AESCipher(int passwordLength, int saltLength, int initializationVectorSeedLength, int hashIterations, KeyLength keylength)
            throws GeneralSecurityException {

        this.passwordLength = passwordLength;
        this.saltLength = saltLength;
        this.initializationVectorSeedLength = initializationVectorSeedLength;
        this.hashIterations = hashIterations;
        this.keyLength = keylength;
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        generateKey();
    }


    public SecretKey getSecretKey() {
        return secretKey;
    }

    public String getEncodedSecretKey(SecretKey secretKey) {
        return Base64.encodeToString(secretKey.getEncoded(), Base64.DEFAULT);
    }

    public SecretKey getDecodedSecretKey(String secretKey) {
        return new SecretKeySpec(Base64.decode(secretKey, Base64.DEFAULT), "AES");
    }

    public BigInteger encrypt(BigInteger raw) throws IOException, GeneralSecurityException {
    	SecureRandom secureRandom = new SecureRandom();
        byte[] seed = secureRandom.generateSeed(initializationVectorSeedLength);
        AlgorithmParameterSpec algorithmParameterSpec = new IvParameterSpec(seed);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, algorithmParameterSpec);
        byte[] encryptedMessageBytes = cipher.doFinal(raw.toByteArray());

        byte[] bytesToEncode = new byte[seed.length + encryptedMessageBytes.length];
        System.arraycopy(seed, 0, bytesToEncode, 0, seed.length);
        System.arraycopy(encryptedMessageBytes, 0, bytesToEncode, seed.length, encryptedMessageBytes.length);

        return new BigInteger(bytesToEncode);
    }

	public void generateKey() throws GeneralSecurityException {
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecureRandom secureRandom = new SecureRandom();

		KeySpec keySpec = new PBEKeySpec(getRandomPassword(), secureRandom.generateSeed(saltLength), hashIterations, keyLength.getBits());
        secretKey = new SecretKeySpec(secretKeyFactory.generateSecret(keySpec).getEncoded(), "AES");
	}

    public BigInteger decrypt(BigInteger encrypted)throws IOException, GeneralSecurityException {

        byte[] bytesToDecode = encrypted.toByteArray();

        byte[] emptySeed = new byte[initializationVectorSeedLength];
        System.arraycopy(bytesToDecode, 0, emptySeed, 0, initializationVectorSeedLength);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(emptySeed));

        int messageDecryptedBytesLength = bytesToDecode.length - initializationVectorSeedLength;
        byte[] messageDecryptedBytes = new byte[messageDecryptedBytesLength];
        System.arraycopy(bytesToDecode, initializationVectorSeedLength, messageDecryptedBytes, 0, messageDecryptedBytesLength);

        return new BigInteger(cipher.doFinal(messageDecryptedBytes));
    }

    public enum KeyLength {

        ONE_TWENTY_EIGHT(128),
        ONE_NINETY_TWO(192),
        TWO_FIFTY_SIX(256);

        private int bits;

        KeyLength(int bits) {
            this.bits = bits;
        }

        public int getBits() {
            return bits;
        }
    }

    protected char[] getRandomPassword() {

        char[] randomPassword = new char[passwordLength];

        Random random = new Random();
        for(int i = 0; i < passwordLength; i++) {
            randomPassword[i] = (char)(random.nextInt('~' - '!' + 1) + '!');
        }

        return randomPassword;
    }
}
