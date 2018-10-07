package com.gelecex.ds.encryption.symmetric;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;

/**
 * Created by obetron on 7.10.2018
 */
public class DSSymmetricEncryptionTest {

    public DSSymmetricEncryption symmetricEncryption = new DSEncryption();

    @Test
    public void encryptTest() {
        Assertions.assertThrows(UnsupportedEncodingException.class, () -> {
            byte[] testDataToBeEncrypting = "asdfghjklşi".getBytes("UTF-8");
            Assertions.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting));
        });
    }


    @Test
    public void decryptTest() {
        Assertions.assertThrows(UnsupportedEncodingException.class, () -> {
            byte[] testDataEncrypted = "".getBytes("UTF-8");
            Assertions.assertNotNull(symmetricEncryption.decrypt(testDataEncrypted));
        });
    }
}
