package com.gelecex.ds.encryption.symmetric;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Created by obetron on 7.10.2018
 */
public interface SymmetricKeyX {

    SecretKey generateKeyFromText(String value, SymmetricAlgorithmX algorithm);
    SecretKey generateKeyFromFile(FileInputStream inputStream, SymmetricAlgorithmX algorithm) throws IOException;
    SecretKey getKeyFromSmartcard();

}
