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

    byte[] decrypt(byte[] encryptedData, String keyStr) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, SymmetricEncryptionExceptionX;
    byte[] decrypt(byte[] encryptedData, String keyStr, CipherTypeX cipherTypeX) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, SymmetricEncryptionExceptionX;
    byte[] decrypt(byte[] encryptedData, String keyStr, CipherTypeX cipherTypeX, SymmetricAlgorithmX algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, UnsupportedEncodingException, SymmetricEncryptionExceptionX;

}
