package com.example.securitydemo;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class SecurityUtils {

    private static final int ITERATION_COUNT = 20000;
    private static final int KEY_LENGTH = 256;
    private static final int IV_LENGTH = 16;
    private static final String PBKDF_2_WITH_HMAC_SHA_1 = "PBKDF2WithHmacSHA1";
    private static final String AES = "AES";
    private static final String AES_GCM_NO_PADDING = "AES/GCM/NoPadding";
    private static final String BC = "BC";

    // Salt & IV
    private static byte[] createRandomBytes(int keySize) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] output = new byte[keySize];
        secureRandom.nextBytes(output);

        return output;
    }

    public static byte[] createSalt() {
        return createRandomBytes(KEY_LENGTH);
    }

    public static byte[] createIv() {
        return createRandomBytes(IV_LENGTH);
    }

    // Key Derivation Function
    public static SecretKey createPBKDF2WithHmacSHA1Key(char[] password, byte[] salt) throws
            NoSuchAlgorithmException, InvalidKeySpecException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF_2_WITH_HMAC_SHA_1);
        KeySpec spec = new PBEKeySpec(password, salt, ITERATION_COUNT, KEY_LENGTH);
        SecretKey tmp = factory.generateSecret(spec);

        return new SecretKeySpec(tmp.getEncoded(), AES);
    }

    // Encryption method
    public static byte[] encryptWithAesGcm(byte[] plaintext, SecretKey secretKey, byte[] ivBytes) throws
            NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING, BC);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(ivBytes));

        return cipher.doFinal(plaintext);
    }

    // Decryption method
    public static byte[] decryptWithAesGcm(byte[] encryptedText, SecretKey secretKey, byte[] ivBytes) throws
            NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING, BC);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(ivBytes));

        return cipher.doFinal(encryptedText);
    }
}
