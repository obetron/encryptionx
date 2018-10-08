package com.gelecex.ds.encryption.symmetric;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;

/**
 * Created by obetron on 7.10.2018
 */
public interface DSSymmetricEncryption {

    byte[] encrypt(byte[] dataToBeEncrypted) throws InvalidKeyException;
    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr) throws InvalidKeyException;
    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, String cipherStr) throws InvalidKeyException;
    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, String cipherStr, String algorithm) throws InvalidKeyException;

    byte[] decrypt(byte[] encryptedData);
    byte[] decrypt(byte[] encryptedData, String keyStr);
    byte[] decrypt(byte[] encryptedData, String keyStr, String cipherStr);
    byte[] decrypt(byte[] encryptedData, String keyStr, String cipherStr, String algorithm);
}
