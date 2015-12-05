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
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class SecurityUtils {

    private static final int ITERATION_COUNT = 10000;
    private static final int KEY_LENGTH = 256;
    private static final int IV_LENGTH = 16;
    private static final int EXPECTED_PBKDF_TIME = 800;
    private static final String PBKDF_2_WITH_HMAC_SHA_1 = "PBKDF2WithHmacSHA1";
    private static final String AES = "AES";
    private static final String AES_GCM_NO_PADDING = "AES/GCM/NoPadding";
    private static final String BC = "BC";
    private static final String UTF_8 = "UTF-8";

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

    // Generate key for db
    public static SecretKey createAesKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen;
        keyGen = KeyGenerator.getInstance(AES);
        keyGen.init(KEY_LENGTH);
        return keyGen.generateKey();
    }

    /***************************
     * Key Derivation Function *
     ***************************/

    public static SecretKey createPBKDF2WithHmacSHA1Key(char[] password, byte[] salt, int numOfIteration) throws
            NoSuchAlgorithmException, InvalidKeySpecException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF_2_WITH_HMAC_SHA_1);
        KeySpec spec = new PBEKeySpec(password, salt, numOfIteration, KEY_LENGTH);
        SecretKey tmp = factory.generateSecret(spec);

        return new SecretKeySpec(tmp.getEncoded(), AES);
    }

    public static SecretKey createPBKDF2WithHmacSHA1Key(char[] password, byte[] salt) throws
            NoSuchAlgorithmException, InvalidKeySpecException {
        return createPBKDF2WithHmacSHA1Key(password, salt, ITERATION_COUNT);
    }

    // Dynamic time for PBKDF
    public static int iterationsForPBKDF(char[] password, byte[] salt, int idealDuration)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        int duration1 = durationForPBKDF(password, salt, 10000);
        if (duration1 > idealDuration) { // Taking too long
            int duration2 = durationForPBKDF(password, salt, 4000);
            double slope  = calcSlope(4000, duration2, 10000, duration1);
            double baseDuration = calcBaseY(slope, 4000, duration2);
            return (int) ((idealDuration - baseDuration) / slope);
        }
        else { // Got extra time
            int duration2 = durationForPBKDF(password, salt, 20000);
            double slope = calcSlope(10000, duration1, 20000, duration2);
            double baseDuration = calcBaseY(slope, 10000, duration1);
            return (int) ((idealDuration - baseDuration) / slope);
        }
    }

    private static double calcSlope(int x1, int y1, int x2, int y2) {
        return ((double) y2 - y1) / (x2 - x1);
    }

    private static double calcBaseY(double slope, int x, int y) {
        return y - x * slope;
    }

    private static int durationForPBKDF(char[] password, byte[] salt, int numOfIterations)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        long startTime = System.currentTimeMillis();
        createPBKDF2WithHmacSHA1Key(password, salt, numOfIterations);
        return (int) (System.currentTimeMillis() - startTime);
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
