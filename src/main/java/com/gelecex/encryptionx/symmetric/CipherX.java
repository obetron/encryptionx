package com.gelecex.encryptionx.symmetric;

import com.gelecex.encryptionx.symmetric.exception.SymmetricEncryptionxException;
import com.gelecex.encryptionx.symmetric.util.EncryptionxUtils;
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
    public byte[] getProcessedData() throws SymmetricEncryptionxException {
        if(CipherXType.AES_ECB_PKCS5Padding.equals(cipherXType)) {
            return initCipher(mode, secretKey, cipherXType);
        } else if (CipherXType.AES_CBC_PKCS5Padding.equals(cipherXType) || CipherXType.AES_CBC_NOPadding.equals(cipherXType)) {
            IvParameterSpec iv = new IvParameterSpec(EncryptionxUtils.generateRandomInitialVectorBytes());
            if(CipherXType.AES_CBC_NOPadding.equals(cipherXType) && data.length % 16 != 0) {
                LOGGER.debug("NOPadding not supported with different data length from 16! Data Length: " + data.length);
                cipherXType = CipherXType.AES_CBC_PKCS5Padding;
            }
            return initCipher(mode, secretKey, cipherXType, iv);
        } else {
            throw new SymmetricEncryptionxException("Operation does not supported yet!");
        }
    }

    private byte[] initCipher(int mode, SecretKey secretKey, CipherXType cipherXType) throws SymmetricEncryptionxException {
        return initCipher(mode, secretKey, cipherXType, null);
    }

    private byte[] initCipher(int mode, SecretKey secretKey, CipherXType cipherXType, IvParameterSpec iv) throws SymmetricEncryptionxException {
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
            throw new SymmetricEncryptionxException(cipherXType.getValue() + " is not a valid algorithm for create cipher instance!");
        } catch (NoSuchPaddingException e) {
            throw new SymmetricEncryptionxException("Padding error, no such padding!");
        } catch (InvalidKeyException e) {
            throw new SymmetricEncryptionxException("Secret key is an invalid!");
        } catch (InvalidAlgorithmParameterException e) {
            throw new SymmetricEncryptionxException("Invalid algorithm for encryption!");
        } catch (IllegalBlockSizeException e) {
            throw new SymmetricEncryptionxException("Illegal black size for encryption!");
        } catch (BadPaddingException e) {
            throw new SymmetricEncryptionxException("Bad padding for encryption!");
        }
    }
}
