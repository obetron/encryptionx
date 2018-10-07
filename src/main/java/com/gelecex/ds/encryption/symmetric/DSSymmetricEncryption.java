package com.gelecex.ds.encryption.symmetric;

import javax.crypto.SecretKey;

/**
 * Created by obetron on 7.10.2018
 */
public interface DSSymmetricEncryption {

    byte[] encrypt(byte[] dataToBeEncrypting);

    byte[] decrypt(byte[] dataToBeEncrypted);
}
