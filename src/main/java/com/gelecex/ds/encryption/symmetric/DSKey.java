package com.gelecex.ds.encryption.symmetric;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Created by obetron on 7.10.2018
 */
public class DSKey implements DSSymmetricKey {

    @Override
    public SecretKey generateKeyFromText(String value, DSSymmetricAlgorithm algorithm) {
        SecretKey secretKey = new SecretKeySpec(value.getBytes(), algorithm.getValue());
        return secretKey;
    }

    @Override
    public SecretKey generateKeyFromFile(FileInputStream fileInputStream, DSSymmetricAlgorithm algorithm) throws IOException {

        int read;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        while((read = fileInputStream.read()) != -1) {
            byteArrayOutputStream.write(read);
        }

        byteArrayOutputStream.flush();
        byteArrayOutputStream.close();

        SecretKey secretKey = new SecretKeySpec(byteArrayOutputStream.toByteArray(), algorithm.getValue());

        return secretKey;
    }

    @Override
    public SecretKey getKeyFromSmartcard() {
        return new SecretKeySpec(new byte[0], "AES");
    }
}
