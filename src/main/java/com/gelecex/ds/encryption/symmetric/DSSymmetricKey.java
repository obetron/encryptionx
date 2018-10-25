package com.gelecex.ds.encryption.symmetric;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Created by obetron on 7.10.2018
 */
public interface DSSymmetricKey {

    SecretKey generateKeyFromText(String value, DSSymmetricAlgorithm algorithm);
    SecretKey generateKeyFromFile(FileInputStream inputStream, DSSymmetricAlgorithm algorithm) throws IOException;
    SecretKey getKeyFromSmartcard();

}
