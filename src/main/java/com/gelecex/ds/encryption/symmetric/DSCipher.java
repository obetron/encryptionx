package com.gelecex.ds.encryption.symmetric;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by obetron on 24.10.2018
 */
public class DSCipher {

    private static final String defaultKeyStr = "1234567890123456";
    private static DSCipher dsCipher;

    private int mode;
    private DSCipherType dsCipherType;
    private SecretKey secretKey;
    private byte[] data;

    /**
     * Constructor
     * @param mode
     * @param dsCipherType
     * @param secretKey
     * @param data
     */
    public DSCipher(int mode, DSCipherType dsCipherType, SecretKey secretKey, byte[] data){
        this.mode = mode;
        this.dsCipherType = dsCipherType;
        this.secretKey = secretKey;
        this.data = data;
    }

    /**
     * Encrypt or decrypt data depends on mode.
     * @return encrypted or decrypted data depends on mode.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public byte[] getData() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(dsCipherType.getValue());
        if(dsCipherType.equals(DSCipherType.AES_CBC_PKCS5Padding)) {
            IvParameterSpec iv = new IvParameterSpec(defaultKeyStr.getBytes());
            cipher.init(mode, secretKey, iv);
        } else if(dsCipherType.equals(DSCipherType.AES_ECB_PKCS5Padding)) {
            cipher.init(mode, secretKey);
        }
        byte[] encryptedResult = cipher.doFinal(data);
        return encryptedResult;
    }

}
