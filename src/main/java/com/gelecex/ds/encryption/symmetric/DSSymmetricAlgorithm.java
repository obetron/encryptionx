package com.gelecex.ds.encryption.symmetric;

/**
 * Created by obetron on 24.10.2018
 */
public enum DSSymmetricAlgorithm {

    AES("AES"),
    Blowfish("Blowfish"),
    DESede("DESede"),
    RC2("RC2");

    private String value;

    private DSSymmetricAlgorithm(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
