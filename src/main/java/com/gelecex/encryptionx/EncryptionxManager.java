package com.gelecex.encryptionx;

import com.gelecex.encryptionx.symmetric.exception.SymmetricEncryptionxException;
import com.gelecex.encryptionx.symmetric.*;

import java.security.PublicKey;

/**
 * @author Eren Basaran - adm
 * Tarih: 1/6/2021 9:08 PM
 */
public class EncryptionxManager {

    private SymmetricEncryption symmetricEncryption;
    private SymmetricDecryption symmetricDecryption;

    public byte[] encryptSymmetric(byte[] dataToBeEncrypted, String keyStr) throws SymmetricEncryptionxException {
        symmetricEncryption = new SymmetricEncryptionImpl();
        return symmetricEncryption.encrypt(dataToBeEncrypted, keyStr);
    }

    public byte[] encryptSymmetric(byte[] dataToBeEncrypted, String keyStr, CipherXType cipherType) throws SymmetricEncryptionxException {
        symmetricEncryption = new SymmetricEncryptionImpl();
        return symmetricEncryption.encrypt(dataToBeEncrypted, keyStr, cipherType);
    }

    public byte[] encryptSymmetric(byte[] dataToBeEncrypted, String keyStr, CipherXType cipherType, EnumSymmetricAlgorithm symmetricAlgorithm) throws SymmetricEncryptionxException {
        symmetricEncryption = new SymmetricEncryptionImpl();
        return symmetricEncryption.encrypt(dataToBeEncrypted, keyStr, cipherType, symmetricAlgorithm);
    }

    public byte[] encryptSymmetric(byte[] dataToBeEncrypted, PublicKey secretKey) throws SymmetricEncryptionxException {
        symmetricEncryption = new SymmetricEncryptionImpl();
        return symmetricEncryption.encrypt(dataToBeEncrypted, secretKey);
    }

    public byte[] encryptSymmetric(byte[] dataToBeEncrypted, byte[] publicKeyBytes) throws SymmetricEncryptionxException {
        symmetricEncryption = new SymmetricEncryptionImpl();
        return symmetricEncryption.encrypt(dataToBeEncrypted, publicKeyBytes);
    }

    public byte[] decryptSymmetric(byte[] dataToBeDecrypted, String keyStr) throws SymmetricEncryptionxException {
        symmetricDecryption = new SymmetricDecryptionImpl();
        return symmetricDecryption.decrypt(dataToBeDecrypted, keyStr);
    }

    public byte[] decryptSymmetric(byte[] dataToBeDecrypted, String keyStr, CipherXType cipherType) throws SymmetricEncryptionxException {
        symmetricDecryption = new SymmetricDecryptionImpl();
        return symmetricDecryption.decrypt(dataToBeDecrypted, keyStr, cipherType);
    }

    public byte[] decryptSymmetric(byte[] dataToBeDecrypted, String keyStr, CipherXType cipherType, EnumSymmetricAlgorithm symmetricAlgorithm) throws SymmetricEncryptionxException {
        symmetricDecryption = new SymmetricDecryptionImpl();
        return symmetricDecryption.decrypt(dataToBeDecrypted, keyStr, cipherType, symmetricAlgorithm);
    }

}
