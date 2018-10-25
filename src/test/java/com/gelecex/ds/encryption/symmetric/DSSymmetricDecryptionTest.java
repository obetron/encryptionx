package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.symmetric.util.DSUtils;
import org.apache.log4j.Logger;
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
 * Created by obetron on 9.10.2018
 */
public class DSSymmetricDecryptionTest {

    private static Logger LOGGER = Logger.getLogger(DSSymmetricDecryptionTest.class);
    private DSSymmetricEncryption dsEncryption = new DSEncryption();
    private DSSymmetricDecryption dsDecryption = new DSDecryption();
    private String defaultKey = "1234567890123456";

    @Test
    public void decryptDataTest() throws BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException {
        String dataToBeEncrypted = "Test Value";
        LOGGER.debug("encyption starting");
        byte[] encryptedData = dsEncryption.encrypt(dataToBeEncrypted.getBytes("UTF-8"), defaultKey, DSCipherType.AES_CBC_PKCS5Padding, DSSymmetricAlgorithm.AES);
        LOGGER.debug("encryption done");
        LOGGER.debug("decryption starting");
        byte[] decryptedData = dsDecryption.decrypt(encryptedData, defaultKey, DSCipherType.AES_CBC_PKCS5Padding, DSSymmetricAlgorithm.AES);
        LOGGER.debug("decryption done");
        Assertions.assertEquals(DSUtils.bytesToBase64Str(dataToBeEncrypted.getBytes("UTF-8")), DSUtils.bytesToBase64Str(decryptedData));
    }

}
