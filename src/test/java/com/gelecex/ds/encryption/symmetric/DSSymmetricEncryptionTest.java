package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.symmetric.exception.DSSymmetricEncryptionException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

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
public class DSSymmetricEncryptionTest {

    public DSSymmetricEncryption symmetricEncryption = new DSEncryption();
    private String defaultKey = "1234567890123456";
    private String defaultEncoding = "UTF-8";

    @Test
    public void encryptDataAndKeyTest() throws UnsupportedEncodingException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, DSSymmetricEncryptionException {
        byte[] testDataToBeEncrypting;
        testDataToBeEncrypting = "gelecex.com".getBytes(defaultEncoding);
        Assertions.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey));
    }

    @Test
    public void encryptDataKeyAndCipher() throws UnsupportedEncodingException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, DSSymmetricEncryptionException, InvalidAlgorithmParameterException {
        byte[] testDataToBeEncrypting;
        testDataToBeEncrypting = "gelecex.com".getBytes(defaultEncoding);
        Assertions.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey, DSCipherType.AES_CBC_PKCS5Padding));
    }

    @Test
    public void encryptDataKeyCipherAndAlgorithm() throws UnsupportedEncodingException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, DSSymmetricEncryptionException {
        byte[] testDataToBeEncrypting;
        testDataToBeEncrypting = "gelecex.com".getBytes(defaultEncoding);
        Assertions.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey, DSCipherType.AES_CBC_PKCS5Padding, DSSymmetricAlgorithm.AES));
    }

    @Test
    public void encryptDataWithCBC() throws UnsupportedEncodingException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, DSSymmetricEncryptionException {
        byte[] testDataToBeEncrypting;
        testDataToBeEncrypting = "gelecex.com".getBytes(defaultEncoding);
        Assertions.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey, DSCipherType.AES_CBC_PKCS5Padding, DSSymmetricAlgorithm.AES));
    }

    @Test
    public void encryptWithAWrongKeySize() {
        Assertions.assertThrows(InvalidKeyException.class, () -> {
            byte[] testDataToBeEncrypting;
            String wrongKeySize = "123456";
            testDataToBeEncrypting = "gelecex.com".getBytes(defaultEncoding);
            symmetricEncryption.encrypt(testDataToBeEncrypting, wrongKeySize);
        });
    }

    @Test
    public void encryptWithAWrongEncoding() {
        Assertions.assertThrows(UnsupportedEncodingException.class, () -> {
            byte[] testDataToBeEncrypting;
            String wrongEncoding = "UTF-12";
            testDataToBeEncrypting = "gelecex.com".getBytes(wrongEncoding);
            symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey, DSCipherType.AES_CBC_PKCS5Padding, DSSymmetricAlgorithm.AES);
        });
    }

    @Test
    public void encryptWithCBCNOPadding()
            throws UnsupportedEncodingException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, DSSymmetricEncryptionException, InvalidKeyException {
        byte[] testDataToBeEncrypting;
        testDataToBeEncrypting = "gelecex.com".getBytes(defaultEncoding);
        Assertions.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey, DSCipherType.AES_CBC_NOPadding, DSSymmetricAlgorithm.AES));
    }

}
