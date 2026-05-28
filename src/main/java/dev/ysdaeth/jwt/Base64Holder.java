package dev.ysdaeth.jwt;

import java.util.Objects;

abstract class Base64Holder {
    private String base64;

    String getBase64() throws NullPointerException {
        return Objects.requireNonNull(base64,"Base64 value is null.");
    }

    void setBase64(String base64){
        this.base64 = base64;
    }
}
