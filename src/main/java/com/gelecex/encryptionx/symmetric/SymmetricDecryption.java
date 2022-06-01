package com.gelecex.encryptionx.symmetric;

import com.gelecex.encryptionx.symmetric.exception.SymmetricEncryptionxException;

/**
 * Created by obetron on 11.10.2018
 */
public interface SymmetricDecryption {

    byte[] decrypt(byte[] encryptedData, String keyStr) throws SymmetricEncryptionxException;
    byte[] decrypt(byte[] encryptedData, String keyStr, CipherXType cipherXType) throws SymmetricEncryptionxException;
    byte[] decrypt(byte[] encryptedData, String keyStr, CipherXType cipherXType, EnumSymmetricAlgorithm algorithm) throws SymmetricEncryptionxException;
}
