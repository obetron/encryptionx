package com.gelecex.ds.encryption;

import com.gelecex.ds.encryption.symmetric.CipherXType;
import com.gelecex.ds.encryption.symmetric.ISymmetricDecryptionX;
import com.gelecex.ds.encryption.symmetric.ISymmetricEncryptionX;
import com.gelecex.ds.encryption.symmetric.SymmetricAlgorithmX;
import com.gelecex.ds.encryption.symmetric.exception.SymmetricEncryptionExceptionX;

/**
 * @author Eren Basaran - adm
 * Tarih: 1/6/2021 9:08 PM
 */
public class Enxryption {

    public byte[] encryptSymmetric(byte[] dataToBeEncrypted, String keyStr) throws SymmetricEncryptionExceptionX {
        ISymmetricEncryptionX symmetricEncryption = new ISymmetricEncryptionX();
        return symmetricEncryption.encrypt(dataToBeEncrypted, keyStr);
    }

    public byte[] encryptSymmetric(byte[] dataToBeEncrypted, String keyStr, CipherXType cipherType) throws SymmetricEncryptionExceptionX {
        ISymmetricEncryptionX symmetricEncryption = new ISymmetricEncryptionX();
        return symmetricEncryption.encrypt(dataToBeEncrypted, keyStr, cipherType);
    }

    public byte[] encryptSymmetric(byte[] dataToBeEncrypted, String keyStr, CipherXType cipherType, SymmetricAlgorithmX symmetricAlgorithm) throws SymmetricEncryptionExceptionX {
        ISymmetricEncryptionX symmetricEncryption = new ISymmetricEncryptionX();
        return symmetricEncryption.encrypt(dataToBeEncrypted, keyStr, cipherType, symmetricAlgorithm);
    }

    public byte[] decryptSymmetric(byte[] dataToBeDecrypted, String keyStr) throws SymmetricEncryptionExceptionX {
        ISymmetricDecryptionX symmetricDecryption = new ISymmetricDecryptionX();
        return symmetricDecryption.decrypt(dataToBeDecrypted, keyStr);
    }

    public byte[] decryptSymmetric(byte[] dataToBeDecrypted, String keyStr, CipherXType cipherType) throws SymmetricEncryptionExceptionX {
        ISymmetricDecryptionX symmetricDecryption = new ISymmetricDecryptionX();
        return symmetricDecryption.decrypt(dataToBeDecrypted, keyStr, cipherType);
    }

    public byte[] decryptSymmetric(byte[] dataToBeDecrypted, String keyStr, CipherXType cipherType, SymmetricAlgorithmX symmetricAlgorithm) throws SymmetricEncryptionExceptionX {
        ISymmetricDecryptionX symmetricDecryption = new ISymmetricDecryptionX();
        return symmetricDecryption.decrypt(dataToBeDecrypted, keyStr, cipherType, symmetricAlgorithm);
    }

}
