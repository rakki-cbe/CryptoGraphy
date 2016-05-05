package com.acelearning.android.cryptography;

/**
 * Created by radhakrishanan on 25/4/16.
 */
public class CryptoModel {
    private  String TextPlain="",Iv,Salt,TextEncrypted="";

    /**
     *
     * @param iv Its a 16 bit key we need add, its private key of the data
     * @param salt Its a 32 bit key we need add, its private key of the data
     */
    public CryptoModel(String iv, String salt) {
        Iv = iv;
        Salt = salt;
    }

    public String getTextPlain() {
        return TextPlain;
    }

    public void setTextPlain(String textPlain) {
        TextPlain = textPlain;
    }

    public String getTextEncrypted() {
        return TextEncrypted;
    }

    public void setTextEncrypted(String textEncrypted) {
        TextEncrypted = textEncrypted;
    }

    public String getIv() {
        return Iv;
    }

    public String getSalt() {
        return Salt;
    }
}
