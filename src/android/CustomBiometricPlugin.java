package com.ravi.biometric;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.util.Log;
import android.hardware.biometrics.BiometricManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Toast;
import android.hardware.fingerprint.FingerprintManager;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;
import java.util.concurrent.Executor;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * This class echoes a string called from JavaScript.
 */
public class CustomBiometricPlugin extends CordovaPlugin {
    private static final String TAG = "com.ravi.biometric";
    private String encryptedString;
    private FingerprintManager fingerprintManager;
    private CancellationSignal cancellationSignal;

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        if (action.equals("coolMethod")) {

            fingerprintManager = (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);

            if (ActivityCompat.checkSelfPermission(this,
                    Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED)
                Log.i(TAG, "Require user permissions");

            if (!fingerprintManager.hasEnrolledFingerprints())
                Log.i(TAG, "No fingerprints enrolled");
            String message = args.getString(0);
            this.coolMethod(message, callbackContext);
            return true;
        }
        return false;
    }

    private void coolMethod(String message, CallbackContext callbackContext) {
        if (message != null && message.length() > 0) {
            callbackContext.success(message);
        } else {
            callbackContext.error("Expected one non-empty string argument.");
        }
    }

    private void showFingerPrintPrompt(Cipher cipher) {
        FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);
        FingerprintManager.AuthenticationCallback fingerPrintCb = getAuthenticationCallback();
        cancellationSignal = new CancellationSignal();
        fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, fingerPrintCb, null);
    }

    private FingerprintManager.AuthenticationCallback getAuthenticationCallback() {
        return new FingerprintManager.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errMsgId, CharSequence errString) {
                Log.i(TAG, errString.toString());
            }

            @Override
            public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
                Log.i(TAG, helpString.toString());
            }

            @Override
            public void onAuthenticationFailed() {
                Log.i(TAG, "Finger print authentication failed");
            }

            @Override
            public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                Log.i(TAG, "Authentication sucessfull");
                try {
                    String decryptedInfo = decrypt(result.getCryptoObject().getCipher(), encryptedString);
                    System.out.println(decryptedInfo);
                } catch (Exception e) {
                    throw new RuntimeException();
                }

            }
        };

    }

    private KeyPair generateUserKeyPair()
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA,
                "AndroidKeyStore");
        keyPairGenerator.initialize(new KeyGenParameterSpec.Builder("User", KeyProperties.PURPOSE_DECRYPT)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1).setUserAuthenticationRequired(true)
                .build());
        return keyPairGenerator.generateKeyPair();
    }

    private String displayUserPubKey(KeyPair kp) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pub_recovered = kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        return pub_recovered.toString();
    }

    private KeyPair getUserKeyPair(String keyName) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (keyStore.containsAlias(keyName)) {
            // Get public key
            PublicKey publicKey = keyStore.getCertificate(keyName).getPublicKey();
            // Get private key
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyName, null);
            // Return a key pair
            return new KeyPair(publicKey, privateKey);
        }
        return null;
    }

    @Nullable
    private Cipher createCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        return Cipher.getInstance("RSA/ECB/PKCS1Padding");
    }

    @Nullable
    private String encrypt(Cipher cipher, byte[] plainText) throws Exception {
        try {
            byte[] enc = cipher.doFinal(plainText);
            return Base64.encodeToString(enc, Base64.DEFAULT);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    private String decrypt(Cipher cipher, String encryptedString) throws Exception {
        byte[] bytes = Base64.decode(encryptedString, Base64.NO_WRAP);
        return new String(cipher.doFinal(bytes));
    }

}
