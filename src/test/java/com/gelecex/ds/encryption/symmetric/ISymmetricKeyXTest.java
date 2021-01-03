package com.gelecex.ds.encryption.symmetric;

import org.junit.Assert;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

/**
 * Created by obetron on 7.10.2018
 */
public class ISymmetricKeyXTest {

    private final ISymmetricKeyX ISymmetricKeyX = new ISymmetricKeyX();

    @Test
    public void getSecretKeyFromTextTest() {
        String testKeyValue = "123456789";
        SecretKey secretKeySpec = ISymmetricKeyX.generateKeyFromText(testKeyValue, SymmetricAlgorithmX.AES);
        Assert.assertNotNull(secretKeySpec);
    }

    @Test
    public void getSecretKeyFromFile() {
        String keyPath = "/resources/test.key";
        Assert.assertThrows(FileNotFoundException.class, () -> {
            FileInputStream fileInputStream = new FileInputStream(keyPath);
            SecretKey secretKeySpec = ISymmetricKeyX.generateKeyFromFile(fileInputStream, SymmetricAlgorithmX.AES);
            Assert.assertNotNull(secretKeySpec);
        });
    }

}
