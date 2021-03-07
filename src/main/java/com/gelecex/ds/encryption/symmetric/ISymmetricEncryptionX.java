package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.symmetric.exception.SymmetricEncryptionXException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by obetron on 7.10.2018
 */
public class ISymmetricEncryptionX implements SymmetricEncryptionX {

    private static final Logger LOGGER = LoggerFactory.getLogger(ISymmetricEncryptionX.class);
    private static final CipherXType defaultCipherType = CipherXType.AES_CBC_PKCS5Padding;
    private static final SymmetricAlgorithmX defaultAlgorithm = SymmetricAlgorithmX.AES;

    /**
     * Create an encrypted data with an input; data and key values.
     * Cipher: "AES/CBC/PKCS5PAdding"
     * Algorithm: "AES" -> from cipher algorithm value.
     * @param dataToBeEncrypted Data To Be Encrypted.
     * @param keyStr Key Value.
     * @return Encrypted data.
     */
    public byte[] encrypt(byte[] dataToBeEncrypted, String keyStr) throws SymmetricEncryptionXException {
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
    public byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, CipherXType cipherType) throws SymmetricEncryptionXException {
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
    public byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, CipherXType cipherType, SymmetricAlgorithmX symmetricAlgorithmX)
            throws SymmetricEncryptionXException {
        ISymmetricKeyX symmetricKeyX = new ISymmetricKeyX();
        LOGGER.debug("Data To Be Encrypted Length: " + dataToBeEncrypted.length);
        SecretKey secretKey = symmetricKeyX.generateKeyFromText(keyStr, symmetricAlgorithmX);
        CipherX cipherX = new CipherX(Cipher.ENCRYPT_MODE, cipherType, secretKey, dataToBeEncrypted);
        return  cipherX.getProcessedData();
    }

    @Override
    public byte[] encrypt(byte[] dataToBeEncrypted, PublicKey secretKey) throws SymmetricEncryptionXException {
        CipherX cipherX = new CipherX(Cipher.ENCRYPT_MODE, defaultCipherType, (SecretKey) secretKey, dataToBeEncrypted);
        return cipherX.getProcessedData();
    }

    @Override
    public byte[] encrypt(byte[] dataToBeEncrypted, byte[] publicKeyBytes) throws SymmetricEncryptionXException {
        try {
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            CipherX cipherX = new CipherX(Cipher.ENCRYPT_MODE, defaultCipherType, (SecretKey) publicKey, dataToBeEncrypted);
            return cipherX.getProcessedData();
        } catch (InvalidKeySpecException e) {
            throw new SymmetricEncryptionXException("");
        } catch (NoSuchAlgorithmException e) {
            throw new SymmetricEncryptionXException("");
        }
    }
}
