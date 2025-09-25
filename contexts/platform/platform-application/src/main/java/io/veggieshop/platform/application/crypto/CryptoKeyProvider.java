package io.veggieshop.platform.application.crypto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import javax.crypto.SecretKey;
import java.util.Optional;

public interface CryptoKeyProvider {
    @NotBlank String currentKeyId(@NotNull CryptoKeyUse use);
    @NotNull SecretKey resolveKey(@NotBlank String keyId, @NotNull CryptoKeyUse use);
    default Optional<KeyMetadata> metadata(String keyId, CryptoKeyUse use) { return Optional.empty(); }
}
