package com.gelecex.ds.encryption.symmetric;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by obetron on 7.10.2018
 */
public interface DSSymmetricEncryption {

    byte[] encrypt(byte[] dataToBeEncrypted) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException;
    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException;
    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, String cipherStr) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException;
    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, String cipherStr, String algorithm) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException;

    byte[] decrypt(byte[] encryptedData) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException;
    byte[] decrypt(byte[] encryptedData, String keyStr) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException;
    byte[] decrypt(byte[] encryptedData, String keyStr, String cipherStr) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException;
    byte[] decrypt(byte[] encryptedData, String keyStr, String cipherStr, String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException;
}
