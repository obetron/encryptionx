package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.exception.DSException;
import com.gelecex.ds.encryption.symmetric.exception.DSSymmetricEncryptionException;
import com.gelecex.ds.encryption.symmetric.util.DSUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by obetron on 29.10.2018
 */
public class DSCipherTest {

    @Test
    public void getDataEncryptionTest() throws UnsupportedEncodingException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, DSSymmetricEncryptionException, InvalidAlgorithmParameterException {
        DSKey dsKey = new DSKey();
        SecretKey defaultSecretKey = dsKey.generateKeyFromText("1234567890123456", DSSymmetricAlgorithm.AES);
        byte[] dataToBeEncryoted = "1234567890".getBytes("UTF-8");
        DSCipher defaultDSCipher = new DSCipher(Cipher.ENCRYPT_MODE, DSCipherType.AES_ECB_PKCS5Padding, defaultSecretKey, dataToBeEncryoted);
        byte[] cipherBytes = defaultDSCipher.getData();
        Assertions.assertNotNull(cipherBytes);
    }

    @Test
    public void getDataDecryptionTest() throws UnsupportedEncodingException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, DSSymmetricEncryptionException, InvalidAlgorithmParameterException, DSException {
        DSKey dsKey = new DSKey();
        SecretKey defaultSecretKey = dsKey.generateKeyFromText("1234567890123456", DSSymmetricAlgorithm.AES);
        String encryptedDataBASE64 = "+jEn8SStUFt5eY7FpaleSA==";
        byte[] encryptedDataBytes = DSUtils.base64StrToBytes(encryptedDataBASE64);
        DSCipher defaultDSCipher = new DSCipher(Cipher.DECRYPT_MODE, DSCipherType.AES_ECB_PKCS5Padding, defaultSecretKey, encryptedDataBytes);
        byte[] cipherBytes = defaultDSCipher.getData();
        Assertions.assertNotNull(cipherBytes);
    }
}
