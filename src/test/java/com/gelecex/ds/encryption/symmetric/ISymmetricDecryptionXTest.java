package com.gelecex.ds.encryption.symmetric;

import com.gelecex.ds.encryption.symmetric.exception.SymmetricEncryptionExceptionX;
import com.gelecex.ds.encryption.symmetric.util.UtilsX;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by obetron on 9.10.2018
 */
public class ISymmetricDecryptionXTest {

    private final SymmetricEncryptionX dsEncryption = new ISymmetricEncryptionX();
    private final SymmetricDecryptionX dsDecryption = new ISymmetricDecryptionX();
    private final Charset defaultEncoding = StandardCharsets.UTF_8;
    private final String defaultKey = "1234567890123456";
    private final String dataToBeEncrypted = "Test Value 12345";

    private byte[] encryptData(CipherTypeX cipherTypeX, SymmetricAlgorithmX symmetricAlgorithmX) throws UnsupportedEncodingException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, SymmetricEncryptionExceptionX {
        return dsEncryption.encrypt(dataToBeEncrypted.getBytes(defaultEncoding), defaultKey, cipherTypeX, symmetricAlgorithmX);
    }

    @Test
    public void decryptDataAESCBC() throws BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, SymmetricEncryptionExceptionX {
        CipherTypeX cipherTypeX = CipherTypeX.AES_CBC_PKCS5Padding;
        SymmetricAlgorithmX symmetricAlgorithmX = SymmetricAlgorithmX.AES;

        byte[] encryptedData = encryptData(cipherTypeX, symmetricAlgorithmX);

        byte[] decryptedData = dsDecryption.decrypt(encryptedData, defaultKey, cipherTypeX, symmetricAlgorithmX);

        Assert.assertEquals(UtilsX.bytesToBase64Str(dataToBeEncrypted.getBytes(defaultEncoding)), UtilsX.bytesToBase64Str(decryptedData));
    }

    @Test
    public void decryptDataAESCBCNoPadding() throws NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, SymmetricEncryptionExceptionX {
        CipherTypeX cipherTypeX = CipherTypeX.AES_CBC_NOPadding;
        SymmetricAlgorithmX symmetricAlgorithmX = SymmetricAlgorithmX.AES;

        byte[] encryptedData = encryptData(cipherTypeX, symmetricAlgorithmX);

        byte[] decryptedData = dsDecryption.decrypt(encryptedData, defaultKey, cipherTypeX, symmetricAlgorithmX);

        Assert.assertEquals(UtilsX.bytesToBase64Str(dataToBeEncrypted.getBytes(defaultEncoding)), UtilsX.bytesToBase64Str(decryptedData));
    }

    @Test
    public void decryptDataAESECB() throws NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, SymmetricEncryptionExceptionX {
        CipherTypeX cipherTypeX = CipherTypeX.AES_ECB_PKCS5Padding;
        SymmetricAlgorithmX symmetricAlgorithmX = SymmetricAlgorithmX.AES;

        byte[] encryptedData = encryptData(cipherTypeX, symmetricAlgorithmX);

        byte[] decryptedData = dsDecryption.decrypt(encryptedData, defaultKey, cipherTypeX, symmetricAlgorithmX);

        Assert.assertEquals(UtilsX.bytesToBase64Str(dataToBeEncrypted.getBytes(defaultEncoding)), UtilsX.bytesToBase64Str(decryptedData));
    }

}
