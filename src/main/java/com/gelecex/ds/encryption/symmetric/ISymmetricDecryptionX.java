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

    private final CipherTypeX defaultCipherType = CipherTypeX.AES_CBC_PKCS5Padding;
    private final SymmetricAlgorithmX defaultAlgorithm = SymmetricAlgorithmX.AES;

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
            throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, SymmetricEncryptionExceptionX {
        return decrypt(encryptedData, keyStr, defaultCipherType, defaultAlgorithm);
    }

    /**
     * Decrypt the encrypted data with an input: data, key and cipher values.
     * Algorithm: "AES"
     * PS: This way is not safe for decrypting, which input values used while encrypting operation
     * these values should be used also decrypting.
     * @param encryptedData Encrypted Data.
     * @param keyStr Key Value.
     * @param cipherTypeX Cipher Value.
     * @return Decrypted Data.
     */
    public byte[] decrypt(byte[] encryptedData, String keyStr, CipherTypeX cipherTypeX)
            throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, SymmetricEncryptionExceptionX {
        return decrypt(encryptedData, keyStr, cipherTypeX, defaultAlgorithm);
    }

    /**
     * Decrypt the encrypted data with an input: data, key, cipher and algorithm values.
     * @param encryptedData Encrypted Data.
     * @param keyStr Key Value.
     * @param cipherTypeX Cipher Value.
     * @param symmetricAlgorithmlgorithmX Algorithm Value.
     * @return Decrypted Data.
     */
    public byte[] decrypt(byte[] encryptedData, String keyStr, CipherTypeX cipherTypeX, SymmetricAlgorithmX symmetricAlgorithmlgorithmX)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, UnsupportedEncodingException, SymmetricEncryptionExceptionX {
        ISymmetricKeyX ISymmetricKeyX = new ISymmetricKeyX();
        SecretKey secretKey = ISymmetricKeyX.generateKeyFromText(keyStr, symmetricAlgorithmlgorithmX);
        CipherX cipherX = new CipherX(Cipher.DECRYPT_MODE, cipherTypeX, secretKey, encryptedData);
        return cipherX.getProcessedData();
    }
}
