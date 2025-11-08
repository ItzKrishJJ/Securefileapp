package com.securefile.core_engine.model;

import lombok.Data;
import java.util.List;

@Data
public class HybridContainer {
    private String encryptedKey;
    private String iv;
    private String cipherText;
    private String signature;
    private List<String> fileNames;
    private String metadata;

    // ✅ Add this
    private String token;
}
