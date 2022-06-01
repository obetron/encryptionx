package com.gelecex.encryptionx.symmetric;

import com.gelecex.encryptionx.symmetric.exception.SymmetricEncryptionxException;
import org.junit.Assert;
import org.junit.Test;
import sun.security.provider.X509Factory;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

/**
 * Created by obetron on 7.10.2018
 */
public class SymmetricEncryptionTest {

    public SymmetricEncryption symmetricEncryption = new SymmetricEncryptionImpl();
    private final String defaultKey = "1234567890123456";
    private final Charset defaultEncoding = StandardCharsets.UTF_8;

    @Test
    public void encryptDataAndKeyTest() throws SymmetricEncryptionxException {
        byte[] testDataToBeEncrypting;
        testDataToBeEncrypting = "gelecex.com".getBytes(defaultEncoding);
        Assert.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey));
    }

    @Test
    public void encryptDataKeyAndCipher() throws SymmetricEncryptionxException {
        byte[] testDataToBeEncrypting;
        testDataToBeEncrypting = "gelecex.com".getBytes(defaultEncoding);
        Assert.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey, CipherXType.AES_CBC_PKCS5Padding));
    }

    @Test
    public void encryptDataKeyCipherAndAlgorithm() throws SymmetricEncryptionxException {
        byte[] testDataToBeEncrypting;
        testDataToBeEncrypting = "gelecex.com".getBytes(defaultEncoding);
        Assert.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey, CipherXType.AES_CBC_PKCS5Padding, EnumSymmetricAlgorithm.AES));
    }

    @Test
    public void encryptDataWithCBC() throws SymmetricEncryptionxException {
        byte[] testDataToBeEncrypting;
        testDataToBeEncrypting = "gelecex.com".getBytes(defaultEncoding);
        Assert.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey, CipherXType.AES_CBC_PKCS5Padding, EnumSymmetricAlgorithm.AES));
    }

    @Test
    public void encryptWithAWrongKeySize() {
        Assert.assertThrows(SymmetricEncryptionxException.class, () -> {
            byte[] testDataToBeEncrypting;
            String wrongKeySize = "123456";
            testDataToBeEncrypting = "gelecex.com".getBytes(defaultEncoding);
            symmetricEncryption.encrypt(testDataToBeEncrypting, wrongKeySize);
        });
    }

    @Test
    public void encryptWithAWrongEncoding() {
        Assert.assertThrows(UnsupportedEncodingException.class, () -> {
            byte[] testDataToBeEncrypting;
            String wrongEncoding = "UTF-12";
            testDataToBeEncrypting = "gelecex.com".getBytes(wrongEncoding);
            symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey, CipherXType.AES_CBC_PKCS5Padding, EnumSymmetricAlgorithm.AES);
        });
    }

    @Test
    public void encryptWithCBCNOPadding() throws SymmetricEncryptionxException {
        byte[] testDataToBeEncrypting = "gelecex.com".getBytes(defaultEncoding);
        Assert.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypting, defaultKey, CipherXType.AES_CBC_NOPadding, EnumSymmetricAlgorithm.AES));
    }

    @Test
    public void encryptedWithX509PublicKey() throws CertificateException, FileNotFoundException, SymmetricEncryptionxException {
        byte[] testDataToBeEncrypted = "gelecex.com".getBytes(defaultEncoding);
        InputStream certStream = SymmetricEncryptionTest.class.getResourceAsStream("/public.cer");
        Certificate certificate = new X509Factory().engineGenerateCertificate(certStream);

        Assert.assertNotNull(symmetricEncryption.encrypt(testDataToBeEncrypted, certificate.getPublicKey()));
    }

}
