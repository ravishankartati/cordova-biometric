package com.ravi.biometric;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.PluginResult;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.Manifest;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.content.pm.PackageManager;
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
    public static final int BIOMETRIC_REQ_CODE = 1;
    public static final int PERMISSION_DENIED_ERROR = 2;
    public static final String BIOMETRIC = Manifest.permission.USE_FINGERPRINT;
    private CallbackContext callbackContext;
    private boolean isSucessfulAuth = false;

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext cb) throws JSONException {
        callbackContext = cb;
        if (action.equals("decryptAfterBiometric")) {
            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {
                    try {
                        String toDecrypt = args.getString(0);
                        String keyStoreName = args.getString(1);
                        decryptAfterBiometric(toDecrypt, keyStoreName);
                    } catch (Exception e) {
                        Log.i(TAG, e.getMessage());
                    }

                }
            });
            return true;
        } else if (action.equals("generatePublicKey")) {
            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {
                    try {
                        int keySize = Integer.parseInt(args.getString(0));
                        String keyStoreName = args.getString(1);
                        callbackContext.success(generatePublicKey(keySize, keyStoreName));
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("cancellFingerprintAuth")) {
            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {
                    try {
                        callbackContext.success(cancellFingerprintAuth());
                    } catch (Exception e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            });
        }
        return false;
    }

    private void decryptAfterBiometric(String toDecrypt, String keyStoreName) {
        fingerprintManager = cordova.getActivity().getApplicationContext().getSystemService(FingerprintManager.class);

        if (!cordova.hasPermission(BIOMETRIC))
            cordova.requestPermission(this, BIOMETRIC_REQ_CODE, BIOMETRIC);

        if (!fingerprintManager.hasEnrolledFingerprints())
            Log.i(TAG, "No fingerprints enrolled");

        try {
            KeyPair kp = getUserKeyPair(keyStoreName);
            Cipher cipherEnc = createCipher();
            cipherEnc.init(Cipher.ENCRYPT_MODE, kp.getPublic());
            encryptedString = encrypt(cipherEnc, toDecrypt.getBytes());
            Cipher cipherDec = createCipher();
            cipherDec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
            showFingerPrintPrompt(cipherDec);
        } catch (Exception e) {
            callbackContext.error("Expected one non-empty string argument.");
        }

    }

    private String encrypt(String toEncrypt, String keyStoreName) {
        try {
            Cipher cipherEnc = createCipher();
            cipherEnc.init(Cipher.ENCRYPT_MODE, getUserKeyPair(keyStoreName).getPublic());
            return encrypt(cipherEnc, toEncrypt.getBytes());
        } catch (Exception e) {
            return e.getMessage();
        }

    }

    private String encrypt(Cipher cipher, byte[] plainText) throws Exception {
        try {
            byte[] enc = cipher.doFinal(plainText);
            return Base64.encodeToString(enc, Base64.DEFAULT);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
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
                Toast.makeText(cordova.getActivity().getApplicationContext(), errString.toString(),
                        Toast.LENGTH_LONG).show();
            }

            @Override
            public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
                Log.i(TAG, helpString.toString());
            }

            @Override
            public void onAuthenticationFailed() {
                Toast.makeText(cordova.getActivity().getApplicationContext(), "Finger print authentication failed",
                        Toast.LENGTH_LONG).show();
                Log.i(TAG, "Finger print authentication failed");
            }

            @Override
            public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                Log.i(TAG, "Authentication sucessfull");
                try {
                    isSucessfulAuth = true;
                    String decryptedInfo = decrypt(result.getCryptoObject().getCipher(), encryptedString);
                    Log.i(TAG, decryptedInfo);
                    callbackContext.success(isSucessfulAuth + "" + decryptedInfo);
                } catch (Exception e) {
                    callbackContext.error(e.getMessage());
                }
            }
        };

    }

    private KeyPair generateUserKeyPair(int size, String keyStoreName)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
                Log.i(TAG, "generateUserKeyPair");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA,
                "AndroidKeyStore");
        keyPairGenerator.initialize(new KeyGenParameterSpec.Builder(keyStoreName, KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(size)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1).setUserAuthenticationRequired(true)
                .build());
        return keyPairGenerator.generateKeyPair();
    }

    private String generatePublicKey(int keySize, String keyStoreName) throws Exception {
        if (getUserKeyPair(keyStoreName) != null) {
            return getUserPublicKey(getUserKeyPair(keyStoreName));
        }
        return getUserPublicKey(generateUserKeyPair(keySize, keyStoreName));
    }

    private String cancellFingerprintAuth() {
        if (cancellationSignal != null && !cancellationSignal.isCanceled()) {
            cancellationSignal.cancel();
            return "Cancelled";
        }
        return "Not cancelled";
    }

    private String getUserPublicKey(KeyPair kp) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pub_recovered = kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        return pub_recovered.toString();
    }

    private KeyPair getUserKeyPair(String keyStoreName) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (keyStore.containsAlias(keyStoreName)) {
            PublicKey publicKey = keyStore.getCertificate(keyStoreName).getPublicKey();
            // Get private key
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyStoreName, null);
            // Return a key pair
            return new KeyPair(publicKey, privateKey);
        }
        return null;
    }

    private Cipher createCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        return Cipher.getInstance("RSA/ECB/PKCS1Padding");
    }

    private String decrypt(Cipher cipher, String encryptedString) throws Exception {
        byte[] bytes = Base64.decode(encryptedString, Base64.NO_WRAP);
        return new String(cipher.doFinal(bytes));
    }

    @Override
    public void onRequestPermissionResult(int requestCode, String[] permissions, int[] grantResults)
            throws JSONException {
        for (int r : grantResults) {
            if (r == PackageManager.PERMISSION_DENIED) {
                callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, PERMISSION_DENIED_ERROR));
                return;
            }
        }
        if (requestCode == BIOMETRIC_REQ_CODE) {
            decryptAfterBiometric("toDecrypt", "keyStoreName");
        }
    }

}
