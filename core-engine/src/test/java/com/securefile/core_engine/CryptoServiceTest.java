package com.securefile.core_engine;

import com.securefile.core_engine.model.HybridContainer;
import com.securefile.core_engine.model.Policy;
import com.securefile.core_engine.service.CryptoService;
import com.securefile.core_engine.util.ZipUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class CryptoServiceTest {

    @Autowired
    private CryptoService cryptoService;

    @Test
    @DisplayName("✅ Hybrid Encrypt → Decrypt Should Return Original Data")
    void testHybridRoundTrip() throws Exception {

        // sample file info
        String filename = "sample.txt";
        byte[] content = "Hello Secure World!".getBytes();

        // zip single file into archive byte[]
        byte[] zipped = ZipUtils.zipSingle(filename, content);

        // encryption policy
        Policy policy = new Policy();
        policy.setRequireSignature(true);

        // do encryption
        HybridContainer container = cryptoService.hybridEncrypt(
                zipped,
                List.of(filename),
                policy
        );

        // validation
        assertNotNull(container.getCipherText(), "Ciphertext should not be null");
        assertNotNull(container.getEncryptedKey(), "Encrypted AES key should not be null");
        assertNotNull(container.getIv(), "IV should not be null");

        // decrypt
        byte[] decrypted = cryptoService.hybridDecrypt(container);

        // validate decrypted output equals original zip
        assertArrayEquals(zipped, decrypted, "Decrypted data should match original zipped data");
    }
}
