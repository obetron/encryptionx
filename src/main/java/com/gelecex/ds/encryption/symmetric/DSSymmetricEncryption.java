package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.symmetric.exception.DSSymmetricEncryptionException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by obetron on 7.10.2018
 */
public interface DSSymmetricEncryption {

    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException;
    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, DSCipherType dsCipherType) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, DSSymmetricEncryptionException, InvalidAlgorithmParameterException;
    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, DSCipherType dsCipherType, DSSymmetricAlgorithm algorithm) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException;

}
