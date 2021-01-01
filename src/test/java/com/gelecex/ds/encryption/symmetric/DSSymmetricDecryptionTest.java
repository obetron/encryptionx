package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.symmetric.exception.DSSymmetricEncryptionException;
import com.gelecex.ds.encryption.symmetric.util.DSUtils;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    private final static Logger LOGGER = LoggerFactory.getLogger(DSSymmetricDecryptionTest.class);
    private DSSymmetricEncryption dsEncryption = new DSEncryption();
    private DSSymmetricDecryption dsDecryption = new DSDecryption();
    private String defaultKey = "1234567890123456";
    private final String dataToBeEncrypted = "Test Value 12345";

    private byte[] encryptData(String dataToBeEncrypted, DSCipherType dsCipherType, DSSymmetricAlgorithm dsSymmetricAlgorithm) throws UnsupportedEncodingException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, DSSymmetricEncryptionException {
        byte[] encryptedData = dsEncryption.encrypt(dataToBeEncrypted.getBytes("UTF-8"), defaultKey, dsCipherType, dsSymmetricAlgorithm);
        return encryptedData;
    }

    @Test
    public void decryptDataAESCBC() throws BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, DSSymmetricEncryptionException {
        DSCipherType dsCipherType = DSCipherType.AES_CBC_PKCS5Padding;
        DSSymmetricAlgorithm dsSymmetricAlgorithm = DSSymmetricAlgorithm.AES;

        byte[] encryptedData = encryptData(dataToBeEncrypted, dsCipherType, dsSymmetricAlgorithm);

        byte[] decryptedData = dsDecryption.decrypt(encryptedData, defaultKey, dsCipherType, dsSymmetricAlgorithm);

        Assert.assertEquals(DSUtils.bytesToBase64Str(dataToBeEncrypted.getBytes("UTF-8")), DSUtils.bytesToBase64Str(decryptedData));
    }

    @Test
    public void decryptDataAESCBCNoPadding() throws NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, DSSymmetricEncryptionException {
        DSCipherType dsCipherType = DSCipherType.AES_CBC_NOPadding;
        DSSymmetricAlgorithm dsSymmetricAlgorithm = DSSymmetricAlgorithm.AES;

        byte[] encryptedData = encryptData(dataToBeEncrypted, dsCipherType, dsSymmetricAlgorithm);

        byte[] decryptedData = dsDecryption.decrypt(encryptedData, defaultKey, dsCipherType, dsSymmetricAlgorithm);

        Assert.assertEquals(DSUtils.bytesToBase64Str(dataToBeEncrypted.getBytes("UTF-8")), DSUtils.bytesToBase64Str(decryptedData));
    }

    @Test
    public void decryptDataAESECB() throws NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, DSSymmetricEncryptionException {
        DSCipherType dsCipherType = DSCipherType.AES_ECB_PKCS5Padding;
        DSSymmetricAlgorithm dsSymmetricAlgorithm = DSSymmetricAlgorithm.AES;

        byte[] encryptedData = encryptData(dataToBeEncrypted, dsCipherType, dsSymmetricAlgorithm);

        byte[] decryptedData = dsDecryption.decrypt(encryptedData, defaultKey, dsCipherType, dsSymmetricAlgorithm);

        Assert.assertEquals(DSUtils.bytesToBase64Str(dataToBeEncrypted.getBytes("UTF-8")), DSUtils.bytesToBase64Str(decryptedData));
    }

}
