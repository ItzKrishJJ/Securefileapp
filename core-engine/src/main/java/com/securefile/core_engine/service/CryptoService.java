package com.securefile.core_engine.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securefile.core_engine.model.HybridContainer;
import com.securefile.core_engine.model.Policy;
import com.securefile.core_engine.util.KeystoreHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;                       // ✅ jakarta, not javax
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
// ✅ correct JDK imports
import java.util.Base64;
import java.util.List;

@Service
public class CryptoService {

    private static final String AES_ALGO = "AES";
    private static final int AES_KEY_BITS = 256;
    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private final KeystoreHelper keystoreHelper;
    private KeyPair rsaKeyPair;
    private final ObjectMapper mapper = new ObjectMapper();

    public CryptoService(KeystoreHelper keystoreHelper) {
        this.keystoreHelper = keystoreHelper;
    }

    @PostConstruct
    public void init() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        rsaKeyPair = keystoreHelper.loadKeyPair();             // ✅ will work once helper is defined
        System.out.println("✅ RSA KeyPair loaded from keystore.");
    }

    // -------------------- HYBRID ENCRYPT --------------------
    public HybridContainer hybridEncrypt(byte[] plaintext, List<String> fileNames, Policy policy) throws Exception {
        // 1. Generate AES key
        KeyGenerator kg = KeyGenerator.getInstance(AES_ALGO);
        kg.init(AES_KEY_BITS);
        SecretKey aesKey = kg.generateKey();

        // 2. AES-GCM encrypt
        byte[] iv = new byte[GCM_IV_BYTES];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(iv);
        Cipher aesCipher = Cipher.getInstance(AES_TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
        byte[] cipherText = aesCipher.doFinal(plaintext);

        // 3. RSA-OAEP wrap AES key
        Cipher rsaCipher = Cipher.getInstance(RSA_TRANSFORMATION);
        OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        rsaCipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic(), oaepParams);
        byte[] wrappedKey = rsaCipher.doFinal(aesKey.getEncoded());

        // 4. Optional signature
        String signatureB64 = null;
        if (policy == null || policy.isRequireSignature()) {
            signatureB64 = sign(cipherText);
        }

        HybridContainer container = new HybridContainer();
        container.setEncryptedKey(Base64.getEncoder().encodeToString(wrappedKey));
        container.setIv(Base64.getEncoder().encodeToString(iv));
        container.setCipherText(Base64.getEncoder().encodeToString(cipherText));
        container.setSignature(signatureB64);
        container.setFileNames(fileNames);
        container.setMetadata(policy == null ? null : mapper.writeValueAsString(policy));
        return container;
    }

    // -------------------- HYBRID DECRYPT --------------------
    public byte[] hybridDecrypt(HybridContainer container) throws Exception {
        byte[] wrappedKey = Base64.getDecoder().decode(container.getEncryptedKey());
        byte[] iv = Base64.getDecoder().decode(container.getIv());
        byte[] cipherText = Base64.getDecoder().decode(container.getCipherText());

        if (container.getSignature() != null) {
            boolean ok = verify(cipherText, container.getSignature());
            if (!ok) throw new SecurityException("Signature verification failed – possible tampering");
        }

        Cipher rsaCipher = Cipher.getInstance(RSA_TRANSFORMATION);
        OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        rsaCipher.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate(), oaepParams);
        byte[] aesKeyBytes = rsaCipher.doFinal(wrappedKey);
        SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, AES_ALGO);

        Cipher aesCipher = Cipher.getInstance(AES_TRANSFORMATION);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        return aesCipher.doFinal(cipherText);
    }

    // -------------------- SIGN / VERIFY --------------------
    public String sign(byte[] data) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(rsaKeyPair.getPrivate());
        signer.update(data);
        return Base64.getEncoder().encodeToString(signer.sign());
    }

    public boolean verify(byte[] data, String sigB64) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(rsaKeyPair.getPublic());
        verifier.update(data);
        byte[] sig = Base64.getDecoder().decode(sigB64);
        return verifier.verify(sig);
    }

    // -------------------- JSON HELPERS --------------------
    public byte[] serializeContainer(HybridContainer container) throws Exception {
        return mapper.writeValueAsBytes(container);
    }

    public HybridContainer deserializeContainer(byte[] bytes) throws Exception {
        return mapper.readValue(bytes, HybridContainer.class);
    }
}
