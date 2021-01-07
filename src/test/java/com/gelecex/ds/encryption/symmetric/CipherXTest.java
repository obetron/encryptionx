package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.symmetric.exception.SymmetricEncryptionXException;
import com.gelecex.ds.encryption.symmetric.util.UtilsX;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

/**
 * Created by obetron on 29.10.2018
 */
public class CipherXTest {

    @Test
    public void getDataEncryptionTest() throws SymmetricEncryptionXException {
        ISymmetricKeyX ISymmetricKeyX = new ISymmetricKeyX();
        SecretKey defaultSecretKey = ISymmetricKeyX.generateKeyFromText("1234567890123456", SymmetricAlgorithmX.AES);
        byte[] dataToBeEncrypted = "1234567890".getBytes(StandardCharsets.UTF_8);
        CipherX defaultCipherX = new CipherX(Cipher.ENCRYPT_MODE, CipherXType.AES_ECB_PKCS5Padding, defaultSecretKey, dataToBeEncrypted);
        byte[] cipherBytes = defaultCipherX.getProcessedData();
        Assert.assertNotNull(cipherBytes);
    }

    @Test
    public void getDataDecryptionTest() throws SymmetricEncryptionXException {
        ISymmetricKeyX ISymmetricKeyX = new ISymmetricKeyX();
        SecretKey defaultSecretKey = ISymmetricKeyX.generateKeyFromText("1234567890123456", SymmetricAlgorithmX.AES);
        String encryptedDataBASE64 = "+jEn8SStUFt5eY7FpaleSA==";
        byte[] encryptedDataBytes = UtilsX.base64StrToBytes(encryptedDataBASE64);
        CipherX defaultCipherX = new CipherX(Cipher.DECRYPT_MODE, CipherXType.AES_ECB_PKCS5Padding, defaultSecretKey, encryptedDataBytes);
        byte[] cipherBytes = defaultCipherX.getProcessedData();
        Assert.assertNotNull(cipherBytes);
    }

    @Test
    public void initCipherTest() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        ISymmetricKeyX ISymmetricKeyX = new ISymmetricKeyX();
        SecretKey secretKey = ISymmetricKeyX.generateKeyFromText("1234567890123456", SymmetricAlgorithmX.AES);
        CipherX cipherX = new CipherX(Cipher.DECRYPT_MODE, CipherXType.AES_ECB_PKCS5Padding, secretKey, "1234567890".getBytes());
        Method initCipherMethod = CipherX.class.getDeclaredMethod("initCipher" , int.class, SecretKey.class, CipherXType.class);
        initCipherMethod.setAccessible(true);
        byte[] byteResult = (byte[]) initCipherMethod.invoke(cipherX, Cipher.ENCRYPT_MODE, secretKey, CipherXType.AES_ECB_PKCS5Padding);
        Assert.assertNotNull(byteResult);
    }

    @Test
    public void initCipherWithIVTest() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        ISymmetricKeyX ISymmetricKeyX = new ISymmetricKeyX();
        SecretKey secretKey = ISymmetricKeyX.generateKeyFromText("1234567890123456", SymmetricAlgorithmX.AES);
        CipherX cipherX = new CipherX(Cipher.ENCRYPT_MODE, CipherXType.AES_CBC_PKCS5Padding, secretKey, "1234567890".getBytes());
        IvParameterSpec iv = new IvParameterSpec("1234567890123456".getBytes());
        Method initCipherMethod = CipherX.class.getDeclaredMethod("initCipher", int.class, SecretKey.class, CipherXType.class, IvParameterSpec.class);
        initCipherMethod.setAccessible(true);
        byte[] result = (byte[]) initCipherMethod.invoke(cipherX, Cipher.ENCRYPT_MODE, secretKey, CipherXType.AES_CBC_PKCS5Padding, iv);
        Assert.assertNotNull(result);
    }
}
