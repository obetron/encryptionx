package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.symmetric.exception.SymmetricEncryptionExceptionX;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by obetron on 7.10.2018
 */
public class ISymmetricEncryptionX implements SymmetricEncryptionX {

    private final static Logger LOGGER = LoggerFactory.getLogger(ISymmetricEncryptionX.class);
    private final CipherTypeX defaultCipherType = CipherTypeX.AES_CBC_PKCS5Padding;
    private final SymmetricAlgorithmX defaultAlgorithm = SymmetricAlgorithmX.AES;

    /**
     * Create an encrypted data with an input; data and key values.
     * Cipher: "AES/CBC/PKCS5PAdding"
     * Algorithm: "AES" -> from cipher algorithm value.
     * @param dataToBeEncrypted Data To Be Encrypted.
     * @param keyStr Key Value.
     * @return Encrypted data.
     */
    public byte[] encrypt(byte[] dataToBeEncrypted, String keyStr)
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, SymmetricEncryptionExceptionX {
        LOGGER.debug("encrypting with default cipher and default algorithm");
        return encrypt(dataToBeEncrypted, keyStr, defaultCipherType, defaultAlgorithm);
    }

    /**
     * Create an encrypted data with an input; data, key and cipher values.
     * Algorithm: "AES"  -> from cipher algorithm value.
     * @param dataToBeEncrypted Data To Be Encrypted.
     * @param keyStr Key Value.
     * @param cipherType Cipher Values "Algorithm/Mode/Padding".
     * @return Encrypted data.
     */
    public byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, CipherTypeX cipherType)
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, SymmetricEncryptionExceptionX {
        LOGGER.debug("encrypting with cipher algorithm");
        return encrypt(dataToBeEncrypted, keyStr, cipherType, defaultAlgorithm);
    }

    /**
     * Create an encrypted data with an input; data, key, cipher and algorithm values.
     * @param dataToBeEncrypted Data To Be Encrypted.
     * @param keyStr Key Value.
     * @param cipherType Cipher Values "Algorithm/Mode/Padding".
     * @param symmetricAlgorithmX Algorithm Value.
     * @return Encrypted Data.
     */
    public byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, CipherTypeX cipherType, SymmetricAlgorithmX symmetricAlgorithmX)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, UnsupportedEncodingException, SymmetricEncryptionExceptionX {
        ISymmetricKeyX ISymmetricKeyX = new ISymmetricKeyX();
        LOGGER.debug("Data To Be Encrypted Length: " + dataToBeEncrypted.length);
        SecretKey secretKey = ISymmetricKeyX.generateKeyFromText(keyStr, symmetricAlgorithmX);
        CipherX cipherX = new CipherX(Cipher.ENCRYPT_MODE, cipherType, secretKey, dataToBeEncrypted);
        return  cipherX.getProcessedData();
    }
}
