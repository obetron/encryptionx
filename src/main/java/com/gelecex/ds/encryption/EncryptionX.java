package com.gelecex.ds.encryption;

import com.gelecex.ds.encryption.symmetric.*;
import com.gelecex.ds.encryption.symmetric.exception.SymmetricEncryptionXException;

import java.security.PublicKey;

/**
 * @author Eren Basaran - adm
 * Tarih: 1/6/2021 9:08 PM
 */
public class EncryptionX {

    private SymmetricEncryptionX symmetricEncryption;
    private SymmetricDecryptionX symmetricDecryption;

    public byte[] encryptSymmetric(byte[] dataToBeEncrypted, String keyStr) throws SymmetricEncryptionXException {
        symmetricEncryption = new ISymmetricEncryptionX();
        return symmetricEncryption.encrypt(dataToBeEncrypted, keyStr);
    }

    public byte[] encryptSymmetric(byte[] dataToBeEncrypted, String keyStr, CipherXType cipherType) throws SymmetricEncryptionXException {
        symmetricEncryption = new ISymmetricEncryptionX();
        return symmetricEncryption.encrypt(dataToBeEncrypted, keyStr, cipherType);
    }

    public byte[] encryptSymmetric(byte[] dataToBeEncrypted, String keyStr, CipherXType cipherType, SymmetricAlgorithmX symmetricAlgorithm) throws SymmetricEncryptionXException {
        symmetricEncryption = new ISymmetricEncryptionX();
        return symmetricEncryption.encrypt(dataToBeEncrypted, keyStr, cipherType, symmetricAlgorithm);
    }

    public byte[] encryptSymmetric(byte[] dataToBeEncrypted, PublicKey secretKey) throws SymmetricEncryptionXException {
        symmetricEncryption = new ISymmetricEncryptionX();
        return symmetricEncryption.encrypt(dataToBeEncrypted, secretKey);
    }

    public byte[] encryptSymmetric(byte[] dataToBeEncrypted, byte[] publicKeyBytes) throws SymmetricEncryptionXException {
        symmetricEncryption = new ISymmetricEncryptionX();
        return symmetricEncryption.encrypt(dataToBeEncrypted, publicKeyBytes);
    }

    public byte[] decryptSymmetric(byte[] dataToBeDecrypted, String keyStr) throws SymmetricEncryptionXException {
        symmetricDecryption = new ISymmetricDecryptionX();
        return symmetricDecryption.decrypt(dataToBeDecrypted, keyStr);
    }

    public byte[] decryptSymmetric(byte[] dataToBeDecrypted, String keyStr, CipherXType cipherType) throws SymmetricEncryptionXException {
        symmetricDecryption = new ISymmetricDecryptionX();
        return symmetricDecryption.decrypt(dataToBeDecrypted, keyStr, cipherType);
    }

    public byte[] decryptSymmetric(byte[] dataToBeDecrypted, String keyStr, CipherXType cipherType, SymmetricAlgorithmX symmetricAlgorithm) throws SymmetricEncryptionXException {
        symmetricDecryption = new ISymmetricDecryptionX();
        return symmetricDecryption.decrypt(dataToBeDecrypted, keyStr, cipherType, symmetricAlgorithm);
    }

}
