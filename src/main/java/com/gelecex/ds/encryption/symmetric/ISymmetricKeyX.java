package com.gelecex.ds.encryption.symmetric;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Created by obetron on 7.10.2018
 */
public class ISymmetricKeyX implements SymmetricKeyX {

    @Override
    public SecretKey generateKeyFromText(String value, SymmetricAlgorithmX algorithm) {
        return new SecretKeySpec(value.getBytes(), algorithm.getValue());
    }

    @Override
    public SecretKey generateKeyFromFile(FileInputStream fileInputStream, SymmetricAlgorithmX algorithm) throws IOException {
        int read;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        while((read = fileInputStream.read()) != -1) {
            byteArrayOutputStream.write(read);
        }

        byteArrayOutputStream.flush();
        byteArrayOutputStream.close();

        return new SecretKeySpec(byteArrayOutputStream.toByteArray(), algorithm.getValue());
    }

    @Override
    public SecretKey getKeyFromSmartcard() {
        return new SecretKeySpec(new byte[0], "AES");
    }
}
