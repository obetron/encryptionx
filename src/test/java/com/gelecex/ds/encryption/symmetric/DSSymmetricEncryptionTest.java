package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.symmetric.exception.DSSymmetricEncryptionException;
import com.gelecex.ds.encryption.symmetric.util.DSUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by obetron on 7.10.2018
 */
public class DSSymmetricEncryptionTest {

    public DSSymmetricEncryption symmetricEncryption = new DSEncryption();
    private String defaultKey = "1234567890123456";
    private String defaultCipher  = "AES/ECB/PKCS5Padding";
    private String defaultAlgorithm = "AES";
    private String defaultEncoding = "UTF-8";

    @Test
    public void encryptDataTest() throws UnsupportedEncodingException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] testDataToBeEncrypting;
        testDataToBeEncrypting = "gelecex.com".getBytes(defaultEncoding);
        Assertions.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting));
    }

    @Test
    public void encryptDataAndKeyTest() throws UnsupportedEncodingException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] testDataToBeEncrypting;
        testDataToBeEncrypting = "gelecex.com".getBytes(defaultEncoding);
        Assertions.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey));
    }

    @Test
    public void encryptDataKeyAndCipher() throws UnsupportedEncodingException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, DSSymmetricEncryptionException {
        byte[] testDataToBeEncrypting;
        testDataToBeEncrypting = "gelecex.com".getBytes(defaultEncoding);
        Assertions.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey, defaultCipher));
    }

    @Test
    public void encryptDataKeyCipherAndAlgorithm() throws UnsupportedEncodingException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] testDataToBeEncrypting;
        testDataToBeEncrypting = "gelecex.com".getBytes(defaultEncoding);
        Assertions.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey, defaultCipher, defaultAlgorithm));
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
            symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey, defaultCipher, defaultAlgorithm);
        });
    }

    @Test
    public void encryptWithWrongCipher() {
        Assertions.assertThrows(NoSuchAlgorithmException.class, () -> {
            byte[] testDataToBeEncrypting = "gelecex.com".getBytes(defaultEncoding);
            symmetricEncryption.encrypt(testDataToBeEncrypting,defaultKey, "AES/ECB/TEST");
            //Same output for "TEST/TEST/TEST" cipher value.
        });
    }

    @Test
    public void encryptionWithWrongAlgorithm() {
        Assertions.assertThrows(InvalidKeyException.class, () -> {
            byte[] testDataToBeEncrypted = "gelecex.com".getBytes(defaultEncoding);
            symmetricEncryption.encrypt(testDataToBeEncrypted, defaultKey, defaultCipher, "TEST");
        });
    }

}
