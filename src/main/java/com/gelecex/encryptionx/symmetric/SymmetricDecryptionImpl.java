package com.gelecex.encryptionx.symmetric;

import com.gelecex.encryptionx.symmetric.exception.SymmetricEncryptionxException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * Created by obetron on 11.10.2018
 */
public class SymmetricDecryptionImpl implements SymmetricDecryption {

    private static final CipherXType defaultCipherType = CipherXType.AES_CBC_PKCS5Padding;
    private static final EnumSymmetricAlgorithm defaultAlgorithm = EnumSymmetricAlgorithm.AES;

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
    public byte[] decrypt(byte[] encryptedData, String keyStr) throws SymmetricEncryptionxException {
        return decrypt(encryptedData, keyStr, defaultCipherType, defaultAlgorithm);
    }

    /**
     * Decrypt the encrypted data with an input: data, key and cipher values.
     * Algorithm: "AES"
     * PS: This way is not safe for decrypting, which input values used while encrypting operation
     * these values should be used also decrypting.
     * @param encryptedData Encrypted Data.
     * @param keyStr Key Value.
     * @param cipherXType Cipher Value.
     * @return Decrypted Data.
     */
    public byte[] decrypt(byte[] encryptedData, String keyStr, CipherXType cipherXType) throws SymmetricEncryptionxException {
        return decrypt(encryptedData, keyStr, cipherXType, defaultAlgorithm);
    }

    /**
     * Decrypt the encrypted data with an input: data, key, cipher and algorithm values.
     * @param encryptedData Encrypted Data.
     * @param keyStr Key Value.
     * @param cipherXType Cipher Value.
     * @param enumSymmetricAlgorithm Algorithm Value.
     * @return Decrypted Data.
     */
    public byte[] decrypt(byte[] encryptedData, String keyStr, CipherXType cipherXType, EnumSymmetricAlgorithm enumSymmetricAlgorithm) throws SymmetricEncryptionxException {
        SymmetricKeyGeneratorImpl symmetricKeyX = new SymmetricKeyGeneratorImpl();
        SecretKey secretKey = symmetricKeyX.generateKeyFromText(keyStr, enumSymmetricAlgorithm);
        CipherX cipherX = new CipherX(Cipher.DECRYPT_MODE, cipherXType, secretKey, encryptedData);
        return cipherX.getProcessedData();
    }
}
