package com.gelecex.encryptionx.symmetric;

import com.gelecex.encryptionx.symmetric.exception.SymmetricEncryptionxException;

import java.security.PublicKey;

/**
 * Created by obetron on 7.10.2018
 */
public interface SymmetricEncryption {

    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr) throws SymmetricEncryptionxException;
    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, CipherXType cipherXType) throws SymmetricEncryptionxException;
    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, CipherXType cipherXType, EnumSymmetricAlgorithm algorithm) throws SymmetricEncryptionxException;
    byte[] encrypt(byte[] dataToBeEncrypted, PublicKey secretKey) throws SymmetricEncryptionxException;
    byte[] encrypt(byte[] dataToBeEncrypted, byte[] publicKeyBytes) throws SymmetricEncryptionxException;

}
