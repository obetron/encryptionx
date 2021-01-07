package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.symmetric.exception.SymmetricEncryptionXException;

import java.security.PublicKey;

/**
 * Created by obetron on 7.10.2018
 */
public interface SymmetricEncryptionX {

    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr) throws SymmetricEncryptionXException;
    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, CipherXType cipherXType) throws SymmetricEncryptionXException;
    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, CipherXType cipherXType, SymmetricAlgorithmX algorithm) throws SymmetricEncryptionXException;
    byte[] encrypt(byte[] dataToBeEncrypted, PublicKey secretKey) throws SymmetricEncryptionXException;
    byte[] encrypt(byte[] dataToBeEncrypted, byte[] publicKeyBytes) throws SymmetricEncryptionXException;

}
