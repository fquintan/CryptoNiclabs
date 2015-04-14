package com.example.powertest;

import android.util.Base64;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by felipe on 4/13/15.
 */
public class AESCipher {

    private Cipher cipher;
    private int passwordLength;
    private int saltLength;
    private int initializationVectorSeedLength;

    public AESCipher()
            throws NoSuchAlgorithmException, NoSuchPaddingException {
        this(16, 16, 16);
    }

    public AESCipher(int passwordLength, int saltLength, int initializationVectorSeedLength)
            throws NoSuchAlgorithmException, NoSuchPaddingException {

        try {
            this.passwordLength = passwordLength;
            this.saltLength = saltLength;
            this.initializationVectorSeedLength = initializationVectorSeedLength;
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw noSuchAlgorithmException;
        } catch (NoSuchPaddingException noSuchPaddingException) {
            throw noSuchPaddingException;
        }
    }

    private SecretKey secretKey;

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public String getEncodedSecretKey(SecretKey secretKey) {
        return Base64.encodeToString(secretKey.getEncoded(), Base64.DEFAULT);
    }

    public SecretKey getDecodedSecretKey(String secretKey) {
        return new SecretKeySpec(Base64.decode(secretKey, Base64.DEFAULT), "AES");
    }

    public String encrypt(String rawText, int hashIterations, KeyLength keyLength)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecureRandom secureRandom = new SecureRandom();

        byte[] seed = secureRandom.generateSeed(initializationVectorSeedLength);
        AlgorithmParameterSpec algorithmParameterSpec = new IvParameterSpec(seed);

        KeySpec keySpec = new PBEKeySpec(getRandomPassword(), secureRandom.generateSeed(saltLength), hashIterations, keyLength.getBits());
        secretKey = new SecretKeySpec(secretKeyFactory.generateSecret(keySpec).getEncoded(), "AES");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, algorithmParameterSpec);
        byte[] encryptedMessageBytes = cipher.doFinal(rawText.getBytes());

        byte[] bytesToEncode = new byte[seed.length + encryptedMessageBytes.length];
        System.arraycopy(seed, 0, bytesToEncode, 0, seed.length);
        System.arraycopy(encryptedMessageBytes, 0, bytesToEncode, seed.length, encryptedMessageBytes.length);

        return Base64.encodeToString(bytesToEncode, Base64.DEFAULT);
    }

    public String decrypt(String encryptedText, SecretKey secretKey)
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        byte[] bytesToDecode = Base64.decode(encryptedText, Base64.DEFAULT);

        byte[] emptySeed = new byte[initializationVectorSeedLength];
        System.arraycopy(bytesToDecode, 0, emptySeed, 0, initializationVectorSeedLength);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(emptySeed));

        int messageDecryptedBytesLength = bytesToDecode.length - initializationVectorSeedLength;
        byte[] messageDecryptedBytes = new byte[messageDecryptedBytesLength];
        System.arraycopy(bytesToDecode, initializationVectorSeedLength, messageDecryptedBytes, 0, messageDecryptedBytesLength);

        return new String(cipher.doFinal(messageDecryptedBytes));
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
