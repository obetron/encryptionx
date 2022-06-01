package com.gelecex.encryptionx.symmetric;

import org.junit.Assert;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

/**
 * Created by obetron on 7.10.2018
 */
public class SymmetricKeyGeneratorTest {

    private final SymmetricKeyGeneratorImpl SymmetricKeyGeneratorImpl = new SymmetricKeyGeneratorImpl();

    @Test
    public void getSecretKeyFromTextTest() {
        String testKeyValue = "123456789";
        SecretKey secretKeySpec = SymmetricKeyGeneratorImpl.generateKeyFromText(testKeyValue, EnumSymmetricAlgorithm.AES);
        Assert.assertNotNull(secretKeySpec);
    }

    @Test
    public void getSecretKeyFromFile() {
        String keyPath = "/resources/test.key";
        Assert.assertThrows(FileNotFoundException.class, () -> {
            FileInputStream fileInputStream = new FileInputStream(keyPath);
            SecretKey secretKeySpec = SymmetricKeyGeneratorImpl.generateKeyFromFile(fileInputStream, EnumSymmetricAlgorithm.AES);
            Assert.assertNotNull(secretKeySpec);
        });
    }

}
