package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.symmetric.exception.SymmetricEncryptionExceptionX;
import com.gelecex.ds.encryption.symmetric.util.UtilsX;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
public class CipherX {

    private final static Logger LOGGER = LoggerFactory.getLogger(CipherX.class);

    private int mode;
    private CipherTypeX cipherTypeX;
    private SecretKey secretKey;
    private byte[] data;

    /**
     * Constructor
     * @param mode
     * @param cipherTypeX
     * @param secretKey
     * @param data
     */
    public CipherX(int mode, CipherTypeX cipherTypeX, SecretKey secretKey, byte[] data){
        this.mode = mode;
        this.cipherTypeX = cipherTypeX;
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
    public byte[] getData() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, SymmetricEncryptionExceptionX {
        if(CipherTypeX.AES_ECB_PKCS5Padding.equals(cipherTypeX)) {
            return initCipher(mode, secretKey, cipherTypeX);
        } else if (CipherTypeX.AES_CBC_PKCS5Padding.equals(cipherTypeX) || CipherTypeX.AES_CBC_NOPadding.equals(cipherTypeX)) {
            IvParameterSpec iv = new IvParameterSpec(UtilsX.generateRandomInitialVectorBytes());
            if(CipherTypeX.AES_CBC_NOPadding.equals(cipherTypeX) && data.length % 16 != 0) {
                LOGGER.debug("NOPadding not supported with different data length from 16! Data Length: " + data.length);
                cipherTypeX = CipherTypeX.AES_CBC_PKCS5Padding;
            }
            return initCipher(mode, secretKey, cipherTypeX, iv);
        } else {
            LOGGER.error("Operation does not supported yet!");
            throw new SymmetricEncryptionExceptionX("Operation does not supported yet!");
        }
    }

    private byte[] initCipher(int mode, SecretKey secretKey, CipherTypeX cipherTypeX, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(cipherTypeX.getValue());
        if(iv == null) {
            cipher.init(mode, secretKey);
        } else {
            cipher.init(mode, secretKey, iv);
        }
        return cipher.doFinal(data);
    }

    private byte[] initCipher(int mode, SecretKey secretKey, CipherTypeX cipherTypeX)
            throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
         return initCipher(mode, secretKey, cipherTypeX, null);
    }

}
