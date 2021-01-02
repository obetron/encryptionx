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
 * Created by obetron on 7.10.2018
 */
public interface SymmetricEncryptionX {

    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, SymmetricEncryptionExceptionX;
    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, CipherTypeX cipherTypeX) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, SymmetricEncryptionExceptionX, InvalidAlgorithmParameterException, UnsupportedEncodingException;
    byte[] encrypt(byte[] dataToBeEncrypted, String keyStr, CipherTypeX cipherTypeX, SymmetricAlgorithmX algorithm) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, UnsupportedEncodingException, SymmetricEncryptionExceptionX;

}
