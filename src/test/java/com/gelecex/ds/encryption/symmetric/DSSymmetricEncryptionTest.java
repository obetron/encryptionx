package com.gelecex.ds.encryption.symmetric;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

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
    public void encryptDataTest() {
        byte[] testDataToBeEncrypting;
        try {
            testDataToBeEncrypting = "gelecex.com".getBytes("UTF-8");
            Assertions.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting));
        } catch (UnsupportedEncodingException e) {
            Assertions.assertThrows(UnsupportedEncodingException.class, () -> e.printStackTrace());
        } catch (InvalidKeyException e) {
            Assertions.assertThrows(InvalidKeyException.class, () -> e.printStackTrace());
        }
    }

    @Test
    public void encryptDataAndKeyTest() {
        byte[] testDataToBeEncrypting;
        try {
            testDataToBeEncrypting = "gelecex.com".getBytes("UTF-8");
            Assertions.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey));
        } catch (UnsupportedEncodingException e) {
            Assertions.assertThrows(UnsupportedEncodingException.class, () -> e.printStackTrace());
        } catch (InvalidKeyException e) {
            Assertions.assertThrows(InvalidKeyException.class, () -> e.printStackTrace());
        }
    }

    @Test
    public void encryptDataKeyAndCipher() {
        byte[] testDataToBeEncrypting;
        try {
            testDataToBeEncrypting = "gelecex.com".getBytes("UTF-8");
            Assertions.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey, defaultCipher));
        } catch (UnsupportedEncodingException e) {
            Assertions.assertThrows(UnsupportedEncodingException.class, () -> e.printStackTrace());
        } catch (InvalidKeyException e) {
            Assertions.assertThrows(InvalidKeyException.class, () -> e.printStackTrace());
        }
    }

    @Test
    public void encryptDataKeyCipherAndAlgorithm() {
        byte[] testDataToBeEncrypting;
        try {
            testDataToBeEncrypting = "gelecex.com".getBytes("UTF-8");
            Assertions.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey, defaultCipher, defaultAlgorithm));
        } catch (UnsupportedEncodingException e) {
            Assertions.assertThrows(UnsupportedEncodingException.class, () -> e.printStackTrace());
        } catch (InvalidKeyException e) {
            Assertions.assertThrows(InvalidKeyException.class, () -> e.printStackTrace());
        }
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

    @Test void encryptWithAWrongEncoding() {
        Assertions.assertThrows(UnsupportedEncodingException.class, () -> {
            byte[] testDataToBeEncrypting;
            testDataToBeEncrypting = "gelecex.com".getBytes("UTF-9");
            symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey, defaultCipher, defaultAlgorithm);
        });
    }

//    @Test
//    public void decryptTest() {
//        try {
//            byte[] testDataEncrypted = "".getBytes("UTF-8");
//            Assertions.assertNotNull(symmetricEncryption.decrypt(testDataEncrypted));
//        } catch (UnsupportedEncodingException e) {
//            Assertions.assertThrows(UnsupportedEncodingException.class, () -> e.printStackTrace());
//        }
//    }
}
