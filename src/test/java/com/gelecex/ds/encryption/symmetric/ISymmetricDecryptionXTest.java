package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.symmetric.exception.SymmetricEncryptionXException;
import com.gelecex.ds.encryption.symmetric.util.UtilsX;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Created by obetron on 9.10.2018
 */
public class ISymmetricDecryptionXTest {

    private final SymmetricEncryptionX symmetricEncryptionX = new ISymmetricEncryptionX();
    private final SymmetricDecryptionX symmetricDecryptionX = new ISymmetricDecryptionX();
    private final Charset defaultEncoding = StandardCharsets.UTF_8;
    private final String defaultKey = "1234567890123456";
    private final String dataToBeEncrypted = "Test Value 12345";

    private byte[] encryptData(CipherXType cipherXType, SymmetricAlgorithmX symmetricAlgorithmX) throws SymmetricEncryptionXException {
        return symmetricEncryptionX.encrypt(dataToBeEncrypted.getBytes(defaultEncoding), defaultKey, cipherXType, symmetricAlgorithmX);
    }

    @Test
    public void decryptDataAESCBC() throws SymmetricEncryptionXException {
        CipherXType cipherXType = CipherXType.AES_CBC_PKCS5Padding;
        SymmetricAlgorithmX symmetricAlgorithmX = SymmetricAlgorithmX.AES;
        byte[] encryptedData = encryptData(cipherXType, symmetricAlgorithmX);

        byte[] decryptedData = symmetricDecryptionX.decrypt(encryptedData, defaultKey, cipherXType, symmetricAlgorithmX);
        Assert.assertEquals(UtilsX.bytesToBase64Str(dataToBeEncrypted.getBytes(defaultEncoding)), UtilsX.bytesToBase64Str(decryptedData));
    }

    @Test
    public void decryptDataAESCBCNoPadding() throws SymmetricEncryptionXException {
        CipherXType cipherXType = CipherXType.AES_CBC_NOPadding;
        SymmetricAlgorithmX symmetricAlgorithmX = SymmetricAlgorithmX.AES;
        byte[] encryptedData = encryptData(cipherXType, symmetricAlgorithmX);

        byte[] decryptedData = symmetricDecryptionX.decrypt(encryptedData, defaultKey, cipherXType, symmetricAlgorithmX);
        Assert.assertEquals(UtilsX.bytesToBase64Str(dataToBeEncrypted.getBytes(defaultEncoding)), UtilsX.bytesToBase64Str(decryptedData));
    }

    @Test
    public void decryptDataAESECB() throws SymmetricEncryptionXException {
        CipherXType cipherXType = CipherXType.AES_ECB_PKCS5Padding;
        SymmetricAlgorithmX symmetricAlgorithmX = SymmetricAlgorithmX.AES;
        byte[] encryptedData = encryptData(cipherXType, symmetricAlgorithmX);

        byte[] decryptedData = symmetricDecryptionX.decrypt(encryptedData, defaultKey, cipherXType, symmetricAlgorithmX);
        Assert.assertEquals(UtilsX.bytesToBase64Str(dataToBeEncrypted.getBytes(defaultEncoding)), UtilsX.bytesToBase64Str(decryptedData));
    }

}
