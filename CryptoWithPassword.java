package com.acelearning.android.cryptography;

import android.util.Base64;
import android.util.Log;

import com.acelearning.android.managers.SessionManager;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by radhakrishanan on 25/4/16.
 * Example usage of this class
 * Encryption
 * mCryptoModel=CryptoWithPassword.getInstance().encrypt(Password,PlainText);
 * Decryption
 * mCryptoModel=CryptoWithPassword.getInstance().decrypt(Password,mCryptoModel);//mCryptomodel should contain its salt,IV and the encrypted data
 */
public class CryptoWithPassword {
    private int keyLength = 256;
    private int saltLength = keyLength / 8;
    private int ivLength=16;
    private byte[] salt;
    private byte[] iv;
    public static final int PBE_ITERATION_COUNT = 200; //1024;

    private static final String PBE_ALGORITHM = "PBEWithSHA256And256BitAES-CBC-BC";

    //algorithm / mode / padding
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static CryptoWithPassword ourInstance = new CryptoWithPassword();
    public static CryptoWithPassword getInstance() {
        return ourInstance;
    }

    private CryptoWithPassword() {
     }
    public CryptoModel encrypt(String password, String cleartext) {
        CryptoModel EncData=null;
        Log.d("Plain txt","------>"+cleartext);
        try {
        byte[] encryptedText = null;
        SecureRandom random = new SecureRandom();
        salt = new byte[saltLength];
        random.nextBytes(salt);
        iv = new byte[ivLength];
        random.nextBytes(iv);
         EncData=new CryptoModel(Base64.encodeToString(iv,Base64.DEFAULT),Base64.encodeToString(salt,Base64.DEFAULT));



            PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, PBE_ITERATION_COUNT, keyLength);
            // Taken from the link http://stackoverflow.com/questions/7181532/android-encrypt-string-send-via-https-and-decrypt-string-problem and http://nelenkov.blogspot.in/2012/04/using-password-based-encryption-on.html
            //factory to create the SecretKey, we must indicate the Algorithm
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBE_ALGORITHM);

            SecretKey tmp = factory.generateSecret(pbeKeySpec);

            //Create a key
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

            //We get the key, only for information
            //byte[] key = secret.getEncoded();

            //Cipher class, is used to encrypt using symmetric key algorithms
            Cipher encryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);

            //byte[] iv = generateIv();

            IvParameterSpec ivspec = new IvParameterSpec(iv);

            //Secret Key, parameter specification for an initialization vector
            encryptionCipher.init(Cipher.ENCRYPT_MODE, secret, ivspec);

            //We perform encryption
            encryptedText = encryptionCipher.doFinal(cleartext.getBytes());
            EncData.setTextEncrypted(Base64.encodeToString(encryptedText,Base64.DEFAULT));
            Log.d("Plain txt aft","------>"+decrypt(SessionManager.getPasswordForEncrypt(),EncData).getTextPlain());
          //  Log.d("encrypted=",Base64.encodeToString(encryptedText,Base64.DEFAULT));
        } catch (Exception e) {
            e.printStackTrace();
        }



            return EncData;

    }

    public CryptoModel decrypt(String password,CryptoModel data) {

        String cleartext = "";

        byte[] iv=Base64.decode(data.getIv(),Base64.DEFAULT);
        byte[] salt=Base64.decode(data.getSalt(),Base64.DEFAULT);
        byte[] encryptedText=Base64.decode(data.getTextEncrypted(),Base64.DEFAULT);
        try {

            PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, PBE_ITERATION_COUNT, keyLength);

            //factory to create the SecretKey, we must indicate the Algorithm
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBE_ALGORITHM);

            SecretKey tmp = factory.generateSecret(pbeKeySpec);

            //Create a key
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");



            //Cipher class, is used to encrypt using symmetric key algorithms
            Cipher decryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);

            //byte[] iv = generateIv();

            IvParameterSpec ivspec = new IvParameterSpec(iv);

            //Secret Key, parameter specification for an initialization vector
            decryptionCipher.init(Cipher.DECRYPT_MODE, secret, ivspec);

            //We perform encryption
            byte[] decryptedText = decryptionCipher.doFinal(encryptedText);

            cleartext =  new String(decryptedText);
            data.setTextPlain(cleartext);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return data;
    }
    /****
     */
}
