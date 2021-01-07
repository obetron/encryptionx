package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.symmetric.exception.SymmetricEncryptionXException;

/**
 * Created by obetron on 11.10.2018
 */
public interface SymmetricDecryptionX {

    byte[] decrypt(byte[] encryptedData, String keyStr) throws SymmetricEncryptionXException;
    byte[] decrypt(byte[] encryptedData, String keyStr, CipherXType cipherXType) throws SymmetricEncryptionXException;
    byte[] decrypt(byte[] encryptedData, String keyStr, CipherXType cipherXType, SymmetricAlgorithmX algorithm) throws SymmetricEncryptionXException;
}
