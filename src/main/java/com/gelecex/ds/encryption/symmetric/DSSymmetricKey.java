package com.gelecex.ds.encryption.symmetric;

import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Created by obetron on 7.10.2018
 */
public interface DSSymmetricKey {

    SecretKeySpec getSecretKeyFromText(String value, String algorithm);
    SecretKeySpec getSecretKeyFromFile(FileInputStream inputStream, String algorithm) throws IOException;
    SecretKeySpec getSecretKeyFromSmartCard();

}
