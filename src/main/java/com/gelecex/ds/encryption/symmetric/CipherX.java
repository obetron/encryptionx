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

    private final int mode;
    private CipherXType cipherXType;
    private final SecretKey secretKey;
    private final byte[] data;

    public CipherX(int mode, CipherXType cipherXType, SecretKey secretKey, byte[] data){
        this.mode = mode;
        this.cipherXType = cipherXType;
        this.secretKey = secretKey;
        this.data = data;
    }

    /**
     * Encrypt or decrypt data depends on mode.
     * @return encrypted or decrypted data depends on mode.
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
            throw new SymmetricEncryptionXException("Operation does not supported yet!");
        }
    }

    private byte[] initCipher(int mode, SecretKey secretKey, CipherXType cipherXType) throws SymmetricEncryptionXException {
        return initCipher(mode, secretKey, cipherXType, null);
    }

    private byte[] initCipher(int mode, SecretKey secretKey, CipherXType cipherXType, IvParameterSpec iv) throws SymmetricEncryptionXException {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(cipherXType.getValue());
            if(iv == null) {
                cipher.init(mode, secretKey);
            } else {
                cipher.init(mode, secretKey, iv);
            }
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            throw new SymmetricEncryptionXException(cipherXType.getValue() + " is not a valid algorithm for create cipher instance!");
        } catch (NoSuchPaddingException e) {
            throw new SymmetricEncryptionXException("Padding error, no such padding!");
        } catch (InvalidKeyException e) {
            throw new SymmetricEncryptionXException("Secret key is an invalid!");
        } catch (InvalidAlgorithmParameterException e) {
            throw new SymmetricEncryptionXException("Invalid algorithm for encryption!");
        } catch (IllegalBlockSizeException e) {
            throw new SymmetricEncryptionXException("Illegal black size for encryption!");
        } catch (BadPaddingException e) {
            throw new SymmetricEncryptionXException("Bad padding for encryption!");
        }

    }

}
