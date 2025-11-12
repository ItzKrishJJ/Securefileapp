package com.securefile.core_engine.service;

import com.securefile.core_engine.model.HybridContainer;
import com.securefile.core_engine.model.Policy;
import com.securefile.core_engine.util.KeystoreHelper;
import com.securefile.core_engine.util.PQKeyStore;
import jakarta.annotation.PostConstruct;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.util.Base64;
import java.util.List;

@Service
public class CryptoService {

    private final KeystoreHelper keystoreHelper;
    private final PQKeyStore pqKeyStore;
    private KeyPair rsaKeyPair;

    @Value("${pq.keystore.dir}")
    private String pqKeysDir;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public CryptoService(KeystoreHelper keystoreHelper) {
        this.keystoreHelper = keystoreHelper;
        this.pqKeyStore = new PQKeyStore(java.nio.file.Path.of("D:/SecureFileApp/keystore"));
    }

    @PostConstruct
    public void init() throws Exception {
        // ✅ Load RSA keypair from keystore instead of regenerating every time
        try {
            rsaKeyPair = keystoreHelper.loadKeyPair();
        } catch (Exception ex) {
            System.err.println("⚠️ Could not load keystore key, generating fallback RSA: " + ex.getMessage());
            rsaKeyPair = pqKeyStore.loadOrCreateRSA("fallback_rsa", 2048, null);
        }
    }

    /**
     * Hybrid encrypt using XChaCha20 + RSA fallback.
     */
    public HybridContainer hybridEncrypt(byte[] payloadZip, List<String> filenames, Policy policy, String token) throws Exception {
        byte[] symBytes = new byte[32];
        new SecureRandom().nextBytes(symBytes);
        SecretKey symKey = new SecretKeySpec(symBytes, "XCHACHA20");

        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305", "BC");
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);

        cipher.init(Cipher.ENCRYPT_MODE, symKey, new javax.crypto.spec.IvParameterSpec(nonce));
        byte[] ciphertext = cipher.doFinal(payloadZip);

        // RSA fallback (until PQC integrated)
        byte[] encKey = rsaEncrypt(symBytes, rsaKeyPair.getPublic());

        HybridContainer container = new HybridContainer();
        container.setCiphertext(Base64.getEncoder().encodeToString(ciphertext));
        container.setEncSymmetricKey(Base64.getEncoder().encodeToString(encKey));
        container.setNonce(Base64.getEncoder().encodeToString(nonce));
        container.setFilenames(filenames);
        container.setPolicy(policy);
        container.setToken(token);
        return container;
    }

    public byte[] hybridDecrypt(HybridContainer container) throws Exception {
        byte[] encKey = Base64.getDecoder().decode(container.getEncSymmetricKey());
        byte[] sym = rsaDecrypt(encKey, rsaKeyPair.getPrivate());
        SecretKey symKey = new SecretKeySpec(sym, "XCHACHA20");

        byte[] nonce = Base64.getDecoder().decode(container.getNonce());
        byte[] ct = Base64.getDecoder().decode(container.getCiphertext());

        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305", "BC");
        cipher.init(Cipher.DECRYPT_MODE, symKey, new javax.crypto.spec.IvParameterSpec(nonce));
        return cipher.doFinal(ct);
    }

    private byte[] rsaEncrypt(byte[] data, PublicKey pub) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, pub);
        return rsa.doFinal(data);
    }

    private byte[] rsaDecrypt(byte[] enc, PrivateKey priv) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsa.init(Cipher.DECRYPT_MODE, priv);
        return rsa.doFinal(enc);
    }

    public byte[] serializeContainer(HybridContainer container) throws Exception {
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        return mapper.writeValueAsBytes(container);
    }

    public HybridContainer deserializeContainer(byte[] bytes) throws Exception {
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        return mapper.readValue(bytes, HybridContainer.class);
    }

    public boolean verifyToken(HybridContainer container, String token) {
        return token != null && token.equals(container.getToken());
    }
}
