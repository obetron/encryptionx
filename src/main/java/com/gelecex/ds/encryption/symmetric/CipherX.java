package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.symmetric.exception.SymmetricEncryptionXException;
import com.gelecex.ds.encryption.symmetric.util.UtilsX;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by obetron on 24.10.2018
 */
public class CipherX {

    private final static Logger LOGGER = LoggerFactory.getLogger(CipherX.class);

    private int mode;
    private CipherXType cipherXType;
    private SecretKey secretKey;
    private byte[] data;

    /**
     * Constructor
     * @param mode
     * @param cipherXType
     * @param secretKey
     * @param data
     */
    public CipherX(int mode, CipherXType cipherXType, SecretKey secretKey, byte[] data){
        this.mode = mode;
        this.cipherXType = cipherXType;
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
    public byte[] getProcessedData() throws SymmetricEncryptionXException {
        if(CipherXType.AES_ECB_PKCS5Padding.equals(cipherXType)) {
            return initCipher(mode, secretKey, cipherXType);
        } else if (CipherXType.AES_CBC_PKCS5Padding.equals(cipherXType) || CipherXType.AES_CBC_NOPadding.equals(cipherXType)) {
            IvParameterSpec iv = new IvParameterSpec(UtilsX.generateRandomInitialVectorBytes());
            if(CipherXType.AES_CBC_NOPadding.equals(cipherXType) && data.length % 16 != 0) {
                LOGGER.debug("NOPadding not supported with different data length from 16! Data Length: " + data.length);
                cipherXType = CipherXType.AES_CBC_PKCS5Padding;
            }
            return initCipher(mode, secretKey, cipherXType, iv);
        } else {
            LOGGER.error("Operation does not supported yet!");
            throw new SymmetricEncryptionXException("Operation does not supported yet!");
        }
    }

    private byte[] initCipher(int mode, SecretKey secretKey, CipherXType cipherXType) throws SymmetricEncryptionXException {
        return initCipher(mode, secretKey, cipherXType, null);
    }

    private byte[] initCipher(int mode, SecretKey secretKey, CipherXType cipherXType, IvParameterSpec iv) throws SymmetricEncryptionXException {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(cipherXType.getValue());
            if(iv == null) {
                cipher.init(mode, secretKey);
            } else {
                cipher.init(mode, secretKey, iv);
            }
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("{} is not a valida algorithm for create cipher instance!", cipherXType.getValue());
            throw new SymmetricEncryptionXException(cipherXType.getValue() + " is not a valid algorithm for create cipher instance!");
        } catch (NoSuchPaddingException e) {
            LOGGER.error("Padding error, no such padding!");
            throw new SymmetricEncryptionXException("Padding error, no such padding!");
        } catch (InvalidKeyException e) {
            LOGGER.error("Secret key is an invalid!");
            throw new SymmetricEncryptionXException("Secret key is an invalid!");
        } catch (InvalidAlgorithmParameterException e) {
            LOGGER.error("Invalid algorithm for encryption!");
            throw new SymmetricEncryptionXException("Invalid algorithm for encryption!");
        } catch (IllegalBlockSizeException e) {
            LOGGER.error("Illegal black size for encryption!");
            throw new SymmetricEncryptionXException("Illegal black size for encryption!");
        } catch (BadPaddingException e) {
            LOGGER.error("Bad padding for encryption!");
            throw new SymmetricEncryptionXException("Bad padding for encryption!");
        }

    }

}
