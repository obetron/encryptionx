package com.gelecex.ds.encryption.symmetric.util;

import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

/**
 * Created by obetron on 13.10.2018
 */
public class UtilsXTest {

    @Test
    public void testBytesToBase64Str() {
        byte[] testBytes = "gelecex.com".getBytes();
        String base64Str = UtilsX.bytesToBase64Str(testBytes);

        String calculatedBase64Str = "Z2VsZWNleC5jb20=";
        Assert.assertEquals(calculatedBase64Str, base64Str);
    }

    @Test
    public void testBase64StrToBytes(){
        String testStr = "Z2VsZWNleC5jb20=";
        byte[] decodedBytes = UtilsX.base64StrToBytes(testStr);
        String bytesStr = new String(decodedBytes);

        String calculatedBytes = "gelecex.com";
        Assert.assertEquals(calculatedBytes, bytesStr);
    }

    @Test
    public void testBytesToHex() {
        String testStr = "gelecex.com";
        String hex = UtilsX.bytesToHex(testStr.getBytes(StandardCharsets.UTF_8));

        String calculatedHex = "67656c656365782e636f6d".toUpperCase();
        Assert.assertEquals(calculatedHex, hex);
    }

    @Test
    public void testHexToByte() {
        String hexVal = "67656c656365782e636f6d".toUpperCase();
        byte[] bytes = UtilsX.hexToBytes(hexVal);

        String str = new String(bytes);
        String expectedStr = "gelecex.com";
        Assert.assertEquals(expectedStr, str);
    }

}
