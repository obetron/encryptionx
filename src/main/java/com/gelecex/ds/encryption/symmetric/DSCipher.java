package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.symmetric.exception.DSSymmetricEncryptionException;
import com.gelecex.ds.encryption.symmetric.util.DSUtils;
import org.apache.log4j.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by obetron on 24.10.2018
 */
public class DSCipher {

    private Logger LOGGER = Logger.getLogger(DSCipher.class.getName());

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
    public byte[] getData() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, DSSymmetricEncryptionException {
        if(DSCipherType.AES_ECB_PKCS5Padding.equals(dsCipherType)) {
            return initCipher(mode, secretKey, dsCipherType);
        } else if (DSCipherType.AES_CBC_PKCS5Padding.equals(dsCipherType) || DSCipherType.AES_CBC_NOPadding.equals(dsCipherType)) {
            IvParameterSpec iv = new IvParameterSpec(DSUtils.generateRandomInitialVectorBytes());
            if(DSCipherType.AES_CBC_NOPadding.equals(dsCipherType) && data.length % 16 != 0) {
                LOGGER.debug("NOPadding not supported with different data length from 16! Data Length: " + data.length);
                dsCipherType = DSCipherType.AES_CBC_PKCS5Padding;
            }
            return initCipher(mode, secretKey, dsCipherType, iv);
        } else {
            throw new DSSymmetricEncryptionException("Operation does not supported yet!");
        }
    }

    private byte[] initCipher(int mode, SecretKey secretKey, DSCipherType dsCipherType, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(dsCipherType.getValue());
        if(iv == null) {
            cipher.init(mode, secretKey);
        } else {
            cipher.init(mode, secretKey, iv);
        }
        return cipher.doFinal(data);
    }

    private byte[] initCipher(int mode, SecretKey secretKey, DSCipherType dsCipherType)
            throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
         return initCipher(mode, secretKey, dsCipherType, null);
    }

}
