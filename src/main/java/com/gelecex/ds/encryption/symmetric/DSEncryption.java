package com.gelecex.ds.encryption.symmetric;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by obetron on 7.10.2018
 */
public class DSEncryption implements DSSymmetricEncryption {

    private final String defaultKeyStr = "1234567890123456";
    private final String defaultCipher = "AES/CBC/PKCS5Padding";
    private final String defaultAlgorithm = "AES";

    /**
     * Create an encrypted data with an input; data value.
     * Key: "1234567890123456"
     * Cipher: "AES/CBC/PKCS5Padding"
     * Algorithm: "AES"
     * @param dataToBeEncrypted Data To Be Encrypted.
     * @return Encrypted data.
     */
    public byte[] encrypt(byte[] dataToBeEncrypted)
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return encrypt(dataToBeEncrypted, defaultKeyStr, defaultCipher, defaultAlgorithm);
    }

    /**
     * Create an encrypted data with an input; data and key values.
     * Cipher: "AES/CBC/PKCS5PAdding"
     * Algorithm: "AES"
     * @param dataToBeEncrypted Data To Be Encrypted.
     * @param keyStr Key Value.
     * @return Encrypted data.
     */
    public byte[] encrypt(byte[] dataToBeEncrypted, String keyStr)
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return encrypt(dataToBeEncrypted, keyStr, defaultCipher, defaultAlgorithm);
    }

    /**
     * Create an encrypted data with an input; data, key and cipher values.
     * Algorithm: "AES"
     * @param dataToBeEncrypted Data To Be Encrypted.
     * @param keyStr Key Value.
     * @param cipher Cipher Values "Algorithm/Mode/Padding".
     * @return Encrypted data.
     */
    public byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, String cipher)
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return encrypt(dataToBeEncrypted, keyStr, cipher, defaultAlgorithm);
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
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(cipherStr);
        DSKey dsKey = new DSKey();
        SecretKeySpec secretKeySpec = dsKey.getSecretKeyFromText(keyStr, algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        byte[] cipherValue = cipher.doFinal(dataToBeEncrypted);
        return cipherValue;
    }

    /**
     * Decrypt the encrypted data with an input; data value.
     * Key: "1234567890123456"
     * Cipher: "AES/CBC/PKCS5Padding"
     * Algorithm: "AES"
     * PS: This way is not safe for decrypting, which input values used while encrypting operation
     * these values should be used also decrypting.
     * @param encryptedData Encrypted Data.
     * @return Decrypted Data.
     */
    public byte[] decrypt(byte[] encryptedData)
            throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return decrypt(encryptedData, defaultKeyStr, defaultCipher, defaultAlgorithm);
    }

    /**
     * Decrypt the encrypted data with an input: data and key values.
     * Cipher: "AES/CBC/PKCS5Padding"
     * Algorithm: "AES"
     * PS: This way is not safe for decrypting, which input values used while encrypting operation
     * these values should be used also decrypting.
     * @param encryptedData Encrypted Data.
     * @param keyStr Key Value.
     * @return Decrypted Data.
     */
    public byte[] decrypt(byte[] encryptedData, String keyStr)
            throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return decrypt(encryptedData, keyStr, defaultCipher, defaultAlgorithm);
    }

    /**
     * Decrypt the encrypted data with an input: data, key and cipher values.
     * Algorithm: "AES"
     * PS: This way is not safe for decrypting, which input values used while encrypting operation
     * these values should be used also decrypting.
     * @param encryptedData Encrypted Data.
     * @param keyStr Key Value.
     * @param cipherStr Cipher Value.
     * @return Decrypted Data.
     */
    public byte[] decrypt(byte[] encryptedData, String keyStr, String cipherStr)
            throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return decrypt(encryptedData, keyStr, cipherStr, defaultAlgorithm);
    }

    /**
     * Decrypt the encrypted data with an input: data, key, cipher and algorithm values.
     * @param encryptedData Encrypted Data.
     * @param keyStr Key Value.
     * @param cipherStr Cipher Value.
     * @param algorithm Algorithm Value.
     * @return Decrypted Data.
     */
    public byte[] decrypt(byte[] encryptedData, String keyStr, String cipherStr, String algorithm)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(cipherStr);
        DSKey dsKey = new DSKey();
        SecretKeySpec secretKeySpec = dsKey.getSecretKeyFromText(keyStr, algorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        byte[] decryptedData = cipher.doFinal(encryptedData);
        return decryptedData;
    }
}
