package com.example.powertest;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;

public interface Cipher {
	
	public BigInteger encrypt(BigInteger raw) throws IOException, GeneralSecurityException;
	public BigInteger decrypt(BigInteger encrypted) throws IOException, GeneralSecurityException ;

}
