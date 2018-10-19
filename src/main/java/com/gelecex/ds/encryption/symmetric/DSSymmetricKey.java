package com.gelecex.ds.encryption.symmetric;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Created by obetron on 7.10.2018
 */
public interface DSSymmetricKey {

    SecretKey generateKeyFromText(String value, String algorithm);
    SecretKey generateKeyFromFile(FileInputStream inputStream, String algorithm) throws IOException;
    SecretKey getKeyFromSmartcard();

}
