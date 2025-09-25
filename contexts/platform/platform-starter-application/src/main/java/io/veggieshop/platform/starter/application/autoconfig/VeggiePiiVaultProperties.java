// module: platform-starter-application
package io.veggieshop.platform.starter.application.autoconfig;

import io.veggieshop.platform.infrastructure.pii.PiiVaultJdbcAdapter.PiiVaultConfig;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.Base64;
import java.util.Map;

@ConfigurationProperties(prefix = "veggieshop.pii.vault")
public class VeggiePiiVaultProperties implements PiiVaultConfig {

    private String activeKid = "k1";
    /** map: kid -> key (Base64 أو Hex) */
    private Map<String,String> masterKeys = Map.of();
    private Duration defaultTtl;            // اختياري
    private int maxPayloadBytes = 64 * 1024;
    private int saltBytes = 16;
    private int ivBytes = 12;
    private boolean failIfMissingKey = true;
    private String encoding = "base64";     // "base64" أو "hex"

    // getters/setters ...

    @Override public String getActiveKid(){ return activeKid; }
    @Override public Map<String, String> getMasterKeys(){ return masterKeys; }
    @Override public Duration getDefaultTtl(){ return defaultTtl; }
    @Override public int getMaxPayloadBytes(){ return maxPayloadBytes; }
    @Override public int getSaltBytes(){ return saltBytes; }
    @Override public int getIvBytes(){ return ivBytes; }
    @Override public boolean isFailIfMissingKey(){ return failIfMissingKey; }

    @Override
    public byte[] masterKeyBytes(String kid) {
        if (kid == null || masterKeys == null) return null;
        String raw = masterKeys.get(kid);
        if (raw == null) return null;
        try {
            return "hex".equalsIgnoreCase(encoding)
                    ? hex(raw)
                    : Base64.getDecoder().decode(raw);
        } catch (IllegalArgumentException ex) {
            // مفتاح غير صالح
            return null;
        }
    }

    private static byte[] hex(String s){
        int len = s.length();
        byte[] out = new byte[len/2];
        for (int i=0;i<len;i+=2){
            out[i/2] = (byte)((Character.digit(s.charAt(i),16)<<4)
                    +  Character.digit(s.charAt(i+1),16));
        }
        return out;
    }
}
