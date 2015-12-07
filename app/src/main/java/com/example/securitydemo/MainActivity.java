package com.example.securitydemo;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Set;

import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";
    private static final String UTF_8 = "UTF-8";
    private static final int[] ITERATIONS = {4000, 5000, 6000, 18000, 19000, 20000};

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Setup salt and iv
        byte[] salt = SecurityUtils.createSalt();
        byte[] iv = SecurityUtils.createIv();

        // Create db key
        SecretKey dbKey = null;
        try {
            dbKey = SecurityUtils.createAesKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        // Setup text and password;
        if (dbKey == null)
            return;

        char[] password = "375192".toCharArray();

        byte[] plainText = dbKey.getEncoded();


        for (int i = 0; i < 10; i++) {
            char[] tmp = SecurityUtils.createRandomPassword();
            Log.i(TAG, "onCreate: " + String.valueOf(tmp));
        }

        /*// Calc ideal iteration
        try {
            for (int i = 0; i < 10; i++) {
                int iteration = SecurityUtils.iterationsForPBKDF(password, salt);
                int duration = calcDuration(password, salt, iteration);
                Log.i(TAG, "iteration: " + iteration + "| duration: " + duration);
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }*/

        /*// Gether durations from 4K to 20K
        SecretKey secretKey;
        try {
            for (int i = 0; i < 5; i++)
                experimentDurations(salt, password);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            Log.e(TAG, "onCreate: ", e);
        }*/

        /*// Encrypt
        byte[] encryptedText;
        try {
            encryptedText = SecurityUtils.encryptWithAesGcm(plainText, secretKey, iv);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException
                | NoSuchProviderException | BadPaddingException | InvalidKeyException | IllegalBlockSizeException e) {
            Log.e(TAG, "onCreate: ", e);
            return;
        }

        // Decrypt
        byte[] decryptedText;
        try {
            decryptedText = SecurityUtils.decryptWithAesGcm(encryptedText, secretKey, iv);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException
                | NoSuchProviderException | BadPaddingException | InvalidKeyException | IllegalBlockSizeException e) {
            Log.e(TAG, "onCreate: ", e);
            return;
        }

        if (Arrays.equals(plainText, decryptedText))
            Log.i(TAG, "onCreate: decrypted text matches plaintext");
        else
            Log.i(TAG, "onCreate: decrypted text doesn't match plaintext");*/
    }

    private static void experimentDurations(char[] password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        StringBuilder sb = new StringBuilder();

        int numOfIterations = 4000;
        while (numOfIterations <= 20000) {
            int duration = calcDuration(password, salt, numOfIterations);

            sb.append(duration).append("\t");

            numOfIterations += 1000;
        }
        Log.i(TAG, "experimentDurations: " + sb.toString());
    }

    private static int calcDuration(char[] password, byte[] salt, int numOfIterations)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        long startTime = System.currentTimeMillis();
        SecurityUtils.createPBKDF2WithHmacSHA1Key(password, salt, numOfIterations);
        return (int) (System.currentTimeMillis() - startTime);
    }


    private void printProviders() {
        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            Log.i("CRYPTO","provider: "+provider.getName());
            Set<Provider.Service> services = provider.getServices();
            for (Provider.Service service : services) {
                Log.i("CRYPTO", "  algorithm: " + service.getAlgorithm());
            }
        }
    }


    // Helper methods
    private static String encodeBytesToString(byte[] bytes) {
        return Base64.encodeToString(bytes, Base64.DEFAULT);
    }

    private static byte[] decodeStringToBytes(String string) {
        return Base64.decode(string, Base64.DEFAULT);
    }

    private static byte[] stringToBytes(String string) throws UnsupportedEncodingException {
        return string.getBytes(UTF_8);
    }

    private static String bytesToString(byte[] bytes) throws UnsupportedEncodingException {
        return new String(bytes, UTF_8);
    }
}
