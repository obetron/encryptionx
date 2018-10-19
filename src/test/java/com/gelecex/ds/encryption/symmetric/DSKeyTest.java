package com.gelecex.ds.encryption.symmetric;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

/**
 * Created by obetron on 7.10.2018
 */
public class DSKeyTest {

    private DSKey dsKey = new DSKey();
    private String testAlgorithm = "AES";

    @Test
    public void getSecretKeyFromTextTest() {
            String testKeyValue = "123456789";
            SecretKey secretKeySpec = dsKey.generateKeyFromText(testKeyValue, testAlgorithm);
            Assertions.assertNotNull(secretKeySpec);
    }

    @Test
    public void getSecretKeyFromFile() {
        String keyPath = "/resources/test.key";
        Assertions.assertThrows(FileNotFoundException.class, () -> {
            FileInputStream fileInputStream = new FileInputStream(keyPath);
            SecretKey secretKeySpec = dsKey.generateKeyFromFile(fileInputStream, testAlgorithm);
            Assertions.assertNotNull(secretKeySpec);
        });
    }

}
