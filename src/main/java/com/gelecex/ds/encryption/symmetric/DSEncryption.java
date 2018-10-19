package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.symmetric.util.DSUtils;
import org.apache.log4j.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by obetron on 7.10.2018
 */
public class DSEncryption implements DSSymmetricEncryption {

    private Logger LOGGER = Logger.getLogger(DSEncryption.class);
    private final String defaultKeyStr = "1234567890123456";
    private final String defaultCipher = "AES/ECB/PKCS5Padding";

    /**
     * Create an encrypted data with an input; data value.
     * Key: "1234567890123456"
     * Cipher: "AES/CBC/PKCS5Padding"
     * Algorithm: "AES" -> from cipher algorithm value.
     * @param dataToBeEncrypted Data To Be Encrypted.
     * @return Encrypted data.
     */
    public byte[] encrypt(byte[] dataToBeEncrypted)
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        LOGGER.debug("encrypting with default key, default cipher, default algorithm");
        return encrypt(dataToBeEncrypted, defaultKeyStr, defaultCipher, DSUtils.getAlgFromCipher(defaultCipher));
    }

    /**
     * Create an encrypted data with an input; data and key values.
     * Cipher: "AES/CBC/PKCS5PAdding"
     * Algorithm: "AES" -> from cipher algorithm value.
     * @param dataToBeEncrypted Data To Be Encrypted.
     * @param keyStr Key Value.
     * @return Encrypted data.
     */
    public byte[] encrypt(byte[] dataToBeEncrypted, String keyStr)
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        LOGGER.debug("encrypting with default cipher and default algorithm");
        return encrypt(dataToBeEncrypted, keyStr, defaultCipher, DSUtils.getAlgFromCipher(defaultCipher));
    }

    /**
     * Create an encrypted data with an input; data, key and cipher values.
     * Algorithm: "AES"  -> from cipher algorithm value.
     * @param dataToBeEncrypted Data To Be Encrypted.
     * @param keyStr Key Value.
     * @param cipher Cipher Values "Algorithm/Mode/Padding".
     * @return Encrypted data.
     */
    public byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, String cipher)
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        LOGGER.debug("encrypting with cipher algorithm");
        return encrypt(dataToBeEncrypted, keyStr, cipher, DSUtils.getAlgFromCipher(cipher));
    }

    /**
     * Create an encrypted data with an input; data, key, cipher and algorithm values.
     * @param dataToBeEncrypted Data To Be Encrypted.
     * @param keyStr Key Value.
     * @param cipherStr Cipher Values "Algorithm/Mode/Padding".
     * @param algorithm Algorithm Value.
     * @return Encrypted Data.
     */
    public byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, String cipherStr, String algorithm)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(cipherStr);
        DSKey dsKey = new DSKey();
        SecretKey secretKeySpec = dsKey.generateKeyFromText(keyStr, algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        LOGGER.debug("Required values ok");

        byte[] cipherValue = cipher.doFinal(dataToBeEncrypted);
        LOGGER.debug("Encryption done");
        return cipherValue;
    }
}
