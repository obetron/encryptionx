package com.gelecex.ds.encryption.symmetric;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by obetron on 9.10.2018
 */
public class DSSymmetricDecryptionTest {

    public DSSymmetricEncryption symmetricEncryption = new DSEncryption();
    private String defaultKey = "1234567890123456";
    private String defaultCipher  = "AES/CBC/PKCS5Padding";
    private String defaultAlgorithm = "AES";

    @Test
    public void decryptDataTest() throws BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException {
        String dataToBeEncrypted = "Test Value";
        byte[] encryptedData = symmetricEncryption.encrypt(dataToBeEncrypted.getBytes());
        byte[] decryptedData = symmetricEncryption.decrypt(encryptedData);
        Assertions.assertNotNull(decryptedData);
    }

}
