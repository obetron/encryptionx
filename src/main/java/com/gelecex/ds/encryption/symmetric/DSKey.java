package com.gelecex.ds.encryption.symmetric;

import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Created by obetron on 7.10.2018
 */
public class DSKey implements DSSymmetricKey {

    @Override
    public SecretKeySpec getSecretKeyFromText(String value, String algorithm) {
        SecretKeySpec secretKeySpec = new SecretKeySpec(value.getBytes(), algorithm);
        return secretKeySpec;
    }

    @Override
    public SecretKeySpec getSecretKeyFromFile(FileInputStream fileInputStream, String algorithm) throws IOException {

        int read;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        while((read = fileInputStream.read()) != -1) {
            byteArrayOutputStream.write(read);
        }

        byteArrayOutputStream.flush();
        byteArrayOutputStream.close();

        SecretKeySpec secretKeySpec = new SecretKeySpec(byteArrayOutputStream.toByteArray(), algorithm);

        return secretKeySpec;
    }

    @Override
    public SecretKeySpec getSecretKeyFromSmartCard() {
        return new SecretKeySpec(new byte[0], "AES");
    }
}
