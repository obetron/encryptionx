package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.symmetric.util.DSUtils;
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

    private DSSymmetricEncryption dsEncryption = new DSEncryption();
    private DSSymmetricDecryption dsDecryption = new DSDecryption();
    private String defaultKey = "1234567890123456";
    private String defaultCipher  = "AES/CBC/PKCS5Padding";

    @Test
    public void decryptDataTest() throws BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException {
        String dataToBeEncrypted = "Test Value";
        byte[] encryptedData = dsEncryption.encrypt(dataToBeEncrypted.getBytes(),defaultKey,defaultCipher, DSUtils.getAlgFromCipher(defaultCipher));
        byte[] decryptedData = dsDecryption.decrypt(encryptedData);
        System.out.println(decryptedData.toString());
        Assertions.assertNotNull(decryptedData);
    }

}
