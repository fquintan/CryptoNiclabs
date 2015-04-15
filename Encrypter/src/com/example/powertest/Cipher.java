package com.example.powertest;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;

public interface Cipher {
	
	public String encrypt(String rawText) throws IOException, GeneralSecurityException;
	public String decrypt(String encryptedText) throws IOException, GeneralSecurityException ;

}
