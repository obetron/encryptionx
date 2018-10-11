package com.gelecex.ds.encryption.symmetric;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by obetron on 7.10.2018
 */
public class DSSymmetricEncryptionTest {

    public DSSymmetricEncryption symmetricEncryption = new DSEncryption();
    private String defaultKey = "1234567890123456";
    private String defaultCipher  = "AES/CBC/PKCS5Padding";
    private String defaultAlgorithm = "AES";


    @Test
    public void encryptDataTest() throws UnsupportedEncodingException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] testDataToBeEncrypting;
        testDataToBeEncrypting = "gelecex.com".getBytes("UTF-8");
        Assertions.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting));
    }

    @Test
    public void encryptDataAndKeyTest() throws UnsupportedEncodingException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] testDataToBeEncrypting;
        testDataToBeEncrypting = "gelecex.com".getBytes("UTF-8");
        Assertions.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey));
    }

    @Test
    public void encryptDataKeyAndCipher() throws UnsupportedEncodingException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] testDataToBeEncrypting;
        testDataToBeEncrypting = "gelecex.com".getBytes("UTF-8");
        Assertions.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey, defaultCipher));
    }

    @Test
    public void encryptDataKeyCipherAndAlgorithm() throws UnsupportedEncodingException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] testDataToBeEncrypting;
        testDataToBeEncrypting = "gelecex.com".getBytes("UTF-8");
        Assertions.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey, defaultCipher, defaultAlgorithm));
    }

    @Test
    public void encryptWithAWrongKeySize() {
        Assertions.assertThrows(InvalidKeyException.class, () -> {
            byte[] testDataToBeEncrypting;
            String wrongKeySize = "123456";
            testDataToBeEncrypting = "gelecex.com".getBytes("UTF-8");
            symmetricEncryption.encrypt(testDataToBeEncrypting, wrongKeySize);
        });
    }

    @Test
    public void encryptWithAWrongEncoding() {
        Assertions.assertThrows(UnsupportedEncodingException.class, () -> {
            byte[] testDataToBeEncrypting;
            testDataToBeEncrypting = "gelecex.com".getBytes("UTF-12");
            symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey, defaultCipher, defaultAlgorithm);
        });
    }

    @Test
    public void encryptWithNoSuchPadding() {

    }
}
