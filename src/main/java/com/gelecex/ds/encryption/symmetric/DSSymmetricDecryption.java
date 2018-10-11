package com.gelecex.ds.encryption.symmetric;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by obetron on 11.10.2018
 */
public interface DSSymmetricDecryption {

    byte[] decrypt(byte[] encryptedData) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException;
    byte[] decrypt(byte[] encryptedData, String keyStr) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException;
    byte[] decrypt(byte[] encryptedData, String keyStr, String cipherStr) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException;
    byte[] decrypt(byte[] encryptedData, String keyStr, String cipherStr, String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException;

}
