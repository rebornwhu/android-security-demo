package com.example.securitydemo;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";
    private static final String UTF_8 = "UTF-8";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Setup salt and iv
        byte[] salt = SecurityUtils.createSalt();
        byte[] iv = SecurityUtils.createIv();

        // Setup text and password;
        String clearText = "Android is better than iOS";
        char[] password = "Shawn".toCharArray();

        byte[] plainText;
        try {
             plainText = clearText.getBytes(UTF_8);
        } catch (UnsupportedEncodingException e) {
            Log.e(TAG, "onCreate: ", e);
            return;
        }

        // Create key
        SecretKey secretKey;
        try {
            secretKey = SecurityUtils.createPBKDF2WithHmacSHA1Key(password, salt);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            Log.e(TAG, "onCreate: ", e);
            return;
        }

        // Convert secret key to text
        String keyText = Base64.encodeToString(secretKey.getEncoded(), Base64.DEFAULT);

        // Encrypt
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
            Log.i(TAG, "onCreate: decrypted text doesn't match plaintext");
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
}
