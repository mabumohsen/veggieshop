package io.veggieshop.platform.application.crypto;

public enum CryptoKeyUse {
    AEAD("AES"),
    HMAC("HmacSHA256");

    private final String algorithmFamily;
    CryptoKeyUse(String family) { this.algorithmFamily = family; }
    public String algorithmFamily() { return algorithmFamily; }
}
