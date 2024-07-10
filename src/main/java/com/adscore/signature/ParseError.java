package com.adscore.signature;

public abstract class ParseError extends Exception{
    ParseError(String message) {
        super(message);
    }
}
