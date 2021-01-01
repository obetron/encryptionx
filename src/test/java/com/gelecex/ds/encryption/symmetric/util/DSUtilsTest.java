package com.gelecex.ds.encryption.symmetric.util;

import org.junit.Assert;
import org.junit.Test;

/**
 * Created by obetron on 13.10.2018
 */
public class DSUtilsTest {

    @Test
    public void testBytesToBase64Str() {
        byte[] testBytes = "gelecex.com".getBytes();
        String base64Str = DSUtils.bytesToBase64Str(testBytes);

        String calculatedBase64Str = "Z2VsZWNleC5jb20=";
        Assert.assertEquals(calculatedBase64Str, base64Str);
    }

}
