package com.securefile.core_engine.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Container for hybrid encryption payload.
 * Fields are base64-encoded strings for transport.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class HybridContainer {
    private String encryptedKey;   // base64 RSA-wrapped AES key
    private String iv;             // base64 IV used for AES-GCM
    private String cipherText;     // base64 ciphertext (AES-GCM output)
    private String signature;      // base64 signature over cipherText
    private List<String> fileNames; // original filenames inside the zip
    private String metadata;       // optional JSON string for policy/extra
}
