package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.symmetric.exception.DSSymmetricEncryptionException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by obetron on 7.10.2018
 */
public interface DSSymmetricEncryption {

    byte[] encrypt(byte[] dataToBeEncrypted) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException;
    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException;
    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, String cipherStr) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, DSSymmetricEncryptionException;
    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, String cipherStr, String algorithm) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException;

}
