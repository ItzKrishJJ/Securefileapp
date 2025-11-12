package com.securefile.core_engine.util;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.Base64;

public class PQKeyStore {
    private final Path keysDir;

    public PQKeyStore(Path keysDir) {
        this.keysDir = keysDir;
        try {
            Files.createDirectories(keysDir);
        } catch (IOException e) {
            throw new RuntimeException("Unable to create keys directory", e);
        }
    }

    // Save raw bytes to a file
    private void save(String filename, byte[] data) throws IOException {
        Files.write(keysDir.resolve(filename), data);
    }

    // Load raw bytes from a file
    private byte[] load(String filename) throws IOException {
        return Files.readAllBytes(keysDir.resolve(filename));
    }

    public boolean exists(String filename) {
        return Files.exists(keysDir.resolve(filename));
    }

    // RSA fallback key pair generator (useful until PQC keys are added)
    public KeyPair loadOrCreateRSA(String alias, int bits, char[] pass) throws Exception {
        String pubFile = alias + ".pub";
        String privFile = alias + ".key";

        if (exists(pubFile) && exists(privFile)) {
            byte[] pubBytes = load(pubFile);
            byte[] privBytes = load(privFile);

            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pub = kf.generatePublic(new java.security.spec.X509EncodedKeySpec(pubBytes));
            PrivateKey priv = kf.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(privBytes));
            return new KeyPair(pub, priv);
        } else {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(bits);
            KeyPair kp = kpg.generateKeyPair();
            save(pubFile, kp.getPublic().getEncoded());
            save(privFile, kp.getPrivate().getEncoded());
            return kp;
        }
    }

    // If you add Kyber/Dilithium jars later, add loadOrCreateKyber() and loadOrCreateDilithium() here.
}