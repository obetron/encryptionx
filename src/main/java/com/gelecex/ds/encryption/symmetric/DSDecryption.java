package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.symmetric.util.DSUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by obetron on 11.10.2018
 */
public class DSDecryption implements DSSymmetricDecryption {

    private final String defaultKeyStr = "1234567890123456";
    private final String defaultCipher = "AES/ECB/PKCS5Padding";

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
            throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        return decrypt(encryptedData, defaultKeyStr, defaultCipher, DSUtils.getAlgFromCipher(defaultCipher));
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
            throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        return decrypt(encryptedData, keyStr, defaultCipher, DSUtils.getAlgFromCipher(defaultCipher));
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
            throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        return decrypt(encryptedData, keyStr, cipherStr, DSUtils.getAlgFromCipher(defaultCipher));
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
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(cipherStr);
        DSKey dsKey = new DSKey();
        SecretKey secretKeySpec = dsKey.generateKeyFromText(keyStr, algorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        byte[] decryptedData = cipher.doFinal(encryptedData);
        return decryptedData;
    }
}
