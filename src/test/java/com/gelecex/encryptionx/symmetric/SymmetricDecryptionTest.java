package com.gelecex.encryptionx.symmetric;

import com.gelecex.encryptionx.symmetric.exception.SymmetricEncryptionxException;
import com.gelecex.encryptionx.symmetric.util.EncryptionxUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Created by obetron on 9.10.2018
 */
public class SymmetricDecryptionTest {

    private final SymmetricEncryption symmetricEncryption = new SymmetricEncryptionImpl();
    private final SymmetricDecryption symmetricDecryption = new SymmetricDecryptionImpl();
    private final Charset defaultEncoding = StandardCharsets.UTF_8;
    private final String defaultKey = "1234567890123456";
    private final String dataToBeEncrypted = "Test Value 12345";

    private byte[] encryptData(CipherXType cipherXType, EnumSymmetricAlgorithm enumSymmetricAlgorithm) throws SymmetricEncryptionxException {
        return symmetricEncryption.encrypt(dataToBeEncrypted.getBytes(defaultEncoding), defaultKey, cipherXType, enumSymmetricAlgorithm);
    }

    @Test
    public void decryptDataAESCBC() throws SymmetricEncryptionxException {
        CipherXType cipherXType = CipherXType.AES_CBC_PKCS5Padding;
        EnumSymmetricAlgorithm enumSymmetricAlgorithm = EnumSymmetricAlgorithm.AES;
        byte[] encryptedData = encryptData(cipherXType, enumSymmetricAlgorithm);

        byte[] decryptedData = symmetricDecryption.decrypt(encryptedData, defaultKey, cipherXType, enumSymmetricAlgorithm);
        Assert.assertEquals(EncryptionxUtils.bytesToBase64Str(dataToBeEncrypted.getBytes(defaultEncoding)), EncryptionxUtils.bytesToBase64Str(decryptedData));
    }

    @Test
    public void decryptDataAESCBCNoPadding() throws SymmetricEncryptionxException {
        CipherXType cipherXType = CipherXType.AES_CBC_NOPadding;
        EnumSymmetricAlgorithm enumSymmetricAlgorithm = EnumSymmetricAlgorithm.AES;
        byte[] encryptedData = encryptData(cipherXType, enumSymmetricAlgorithm);

        byte[] decryptedData = symmetricDecryption.decrypt(encryptedData, defaultKey, cipherXType, enumSymmetricAlgorithm);
        Assert.assertEquals(EncryptionxUtils.bytesToBase64Str(dataToBeEncrypted.getBytes(defaultEncoding)), EncryptionxUtils.bytesToBase64Str(decryptedData));
    }

    @Test
    public void decryptDataAESECB() throws SymmetricEncryptionxException {
        CipherXType cipherXType = CipherXType.AES_ECB_PKCS5Padding;
        EnumSymmetricAlgorithm enumSymmetricAlgorithm = EnumSymmetricAlgorithm.AES;
        byte[] encryptedData = encryptData(cipherXType, enumSymmetricAlgorithm);

        byte[] decryptedData = symmetricDecryption.decrypt(encryptedData, defaultKey, cipherXType, enumSymmetricAlgorithm);
        Assert.assertEquals(EncryptionxUtils.bytesToBase64Str(dataToBeEncrypted.getBytes(defaultEncoding)), EncryptionxUtils.bytesToBase64Str(decryptedData));
    }

}
