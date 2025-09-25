package io.veggieshop.platform.starter.application.autoconfig;

import io.veggieshop.platform.application.crypto.*;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.time.Clock;

@AutoConfiguration
@EnableConfigurationProperties(CryptoKeysProperties.class)
public class VeggieCryptoAutoConfiguration {

    @Bean @ConditionalOnMissingBean
    Clock cryptoClock() { return Clock.systemUTC(); }

    @Bean @ConditionalOnMissingBean
    SecureRandom secureRandom() { return new SecureRandom(); }

    /** مزود مفاتيح بسيط للتطوير فقط. في الإنتاج استبدله بمزوّد KMS عبر Bean آخر. */
    @Bean @ConditionalOnMissingBean(CryptoKeyProvider.class)
    CryptoKeyProvider devInMemoryKeyProvider(CryptoKeysProperties p) {
        byte[] aead = java.util.Base64.getDecoder().decode(p.getAead().getSecretBase64());
        byte[] hmac = java.util.Base64.getDecoder().decode(p.getHmac().getSecretBase64());
        SecretKey aeadKey = new SecretKeySpec(aead, "AES");
        SecretKey hmacKey = new SecretKeySpec(hmac, "HmacSHA256");
        final String aeadKid = p.getAead().getKid();
        final String hmacKid = p.getHmac().getKid();

        return new CryptoKeyProvider() {
            @Override public String currentKeyId(CryptoKeyUse use) {
                return (use == CryptoKeyUse.AEAD) ? aeadKid : hmacKid;
            }
            @Override public SecretKey resolveKey(String keyId, CryptoKeyUse use) {
                if (use == CryptoKeyUse.AEAD && aeadKid.equals(keyId)) return aeadKey;
                if (use == CryptoKeyUse.HMAC && hmacKid.equals(keyId)) return hmacKey;
                throw new IllegalArgumentException("Unknown keyId for use=" + use + ": " + keyId);
            }
        };
    }

    @Bean @ConditionalOnMissingBean
    FieldEncryptionService fieldEncryptionService(CryptoKeyProvider provider,
                                                  SecureRandom secureRandom,
                                                  Clock clock) {
        return new FieldEncryptionService(provider, secureRandom, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    HashingService hashingService() {
        return new HashingService();
    }

    @Bean
    @ConditionalOnBean(CryptoKeyProvider.class)
    @ConditionalOnMissingBean
    FieldEncryptionService fieldEncryptionService(CryptoKeyProvider kp) {
        return new FieldEncryptionService(kp);
    }
}
