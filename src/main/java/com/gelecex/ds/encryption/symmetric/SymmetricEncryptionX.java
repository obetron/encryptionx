package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.symmetric.exception.SymmetricEncryptionExceptionX;

import java.security.PublicKey;

/**
 * Created by obetron on 7.10.2018
 */
public interface SymmetricEncryptionX {

    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr) throws SymmetricEncryptionExceptionX;
    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, CipherXType cipherXType) throws SymmetricEncryptionExceptionX;
    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, CipherXType cipherXType, SymmetricAlgorithmX algorithm) throws SymmetricEncryptionExceptionX;
    byte[] encrypt(byte[] dataToBeEncrypted, PublicKey secretKey) throws SymmetricEncryptionExceptionX;

}
