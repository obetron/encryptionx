package com.gelecex.encryptionx.exception;

/**
 * Created by obetron on 13.10.2018
 */
public class EncryptionxException extends Exception {

    public EncryptionxException() {
        super();
    }

    public EncryptionxException(String message) {
        super(message);
    }

    public EncryptionxException(String message, Throwable cause) {
        super(message, cause);
    }

    public EncryptionxException(Throwable cause) {
        super(cause);
    }
}
