package com.gelecex.ds.encryption.exception;

/**
 * Created by obetron on 13.10.2018
 */
public class DSException extends Exception {

    public DSException() {
        super();
    }

    public DSException(String message) {
        super(message);
    }

    public DSException(String message, Throwable cause) {
        super(message, cause);
    }

    public DSException(Throwable cause) {
        super(cause);
    }
}
