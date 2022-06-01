package com.gelecex.encryptionx.symmetric;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Created by obetron on 7.10.2018
 */
public interface SymmetricKeyGenerator {

    SecretKey generateKeyFromText(String value, EnumSymmetricAlgorithm algorithm);
    SecretKey generateKeyFromFile(FileInputStream inputStream, EnumSymmetricAlgorithm algorithm) throws IOException;

}
