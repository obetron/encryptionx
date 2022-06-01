package com.gelecex.encryptionx.symmetric;

/**
 * Created by obetron on 24.10.2018
 */
public enum EnumSymmetricAlgorithm {

    AES("AES"),
    Blowfish("Blowfish"),
    DESede("DESede"),
    RC2("RC2");

    private String value;

    private EnumSymmetricAlgorithm(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
