package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.symmetric.exception.SymmetricEncryptionExceptionX;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by obetron on 11.10.2018
 */
public interface SymmetricDecryptionX {

    byte[] decrypt(byte[] encryptedData, String keyStr) throws SymmetricEncryptionExceptionX;
    byte[] decrypt(byte[] encryptedData, String keyStr, CipherXType cipherXType) throws SymmetricEncryptionExceptionX;
    byte[] decrypt(byte[] encryptedData, String keyStr, CipherXType cipherXType, SymmetricAlgorithmX algorithm) throws SymmetricEncryptionExceptionX;
}
