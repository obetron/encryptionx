package com.gelecex.ds.encryption.symmetric;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by obetron on 7.10.2018
 */
public class DSEncryption implements DSSymmetricEncryption {

    public byte[] encrypt(byte[] dataToBeEncrypting) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/Pkcs5Padding");
            DSKey dsKey = new DSKey();
            SecretKeySpec secretKeySpec = dsKey.getSecretKeyFromText("Test", "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

            byte[] cipherValue = cipher.doFinal(dataToBeEncrypting);
            return cipherValue;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        return null;
    }

    public byte[] decrypt(byte[] dataToBeEncrypted) {

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            DSKey dsKey = new DSKey();
            SecretKeySpec secretKeySpec = dsKey.getSecretKeyFromText("Test", "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

            byte[] decryptedData = cipher.doFinal(dataToBeEncrypted);
            return decryptedData;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        return new byte[0];
    }
}
