package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.symmetric.exception.SymmetricEncryptionExceptionX;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by obetron on 11.10.2018
 */
public class ISymmetricDecryptionX implements SymmetricDecryptionX {

    private static final CipherXType defaultCipherType = CipherXType.AES_CBC_PKCS5Padding;
    private static final SymmetricAlgorithmX defaultAlgorithm = SymmetricAlgorithmX.AES;

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
    public byte[] decrypt(byte[] encryptedData, String keyStr) throws SymmetricEncryptionExceptionX {
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
    public byte[] decrypt(byte[] encryptedData, String keyStr, CipherXType cipherXType) throws SymmetricEncryptionExceptionX {
        return decrypt(encryptedData, keyStr, cipherXType, defaultAlgorithm);
    }

    /**
     * Decrypt the encrypted data with an input: data, key, cipher and algorithm values.
     * @param encryptedData Encrypted Data.
     * @param keyStr Key Value.
     * @param cipherXType Cipher Value.
     * @param symmetricAlgorithmlgorithmX Algorithm Value.
     * @return Decrypted Data.
     */
    public byte[] decrypt(byte[] encryptedData, String keyStr, CipherXType cipherXType, SymmetricAlgorithmX symmetricAlgorithmlgorithmX) throws SymmetricEncryptionExceptionX {
        ISymmetricKeyX ISymmetricKeyX = new ISymmetricKeyX();
        SecretKey secretKey = ISymmetricKeyX.generateKeyFromText(keyStr, symmetricAlgorithmlgorithmX);
        CipherX cipherX = new CipherX(Cipher.DECRYPT_MODE, cipherXType, secretKey, encryptedData);
        return cipherX.getProcessedData();
    }
}
