package com.securefile.core_engine.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;

@Component
public class KeystoreHelper {

	// ✅ Injected from application.properties or environment
	@Value("${keystore.path}")
	private String keystorePath;

	@Value("${keystore.password}")
	private String keystorePassword;

	@Value("${keystore.alias}")
	private String alias;

	/**
	 * Loads an RSA KeyPair (public + private) from a PKCS12 keystore (.p12 or .pfx).
	 */
	public KeyPair loadKeyPair() throws GeneralSecurityException, IOException {
		KeyStore ks = KeyStore.getInstance("PKCS12");

		try (FileInputStream fis = new FileInputStream(keystorePath)) {
			ks.load(fis, keystorePassword.toCharArray());
		}

		Key key = ks.getKey(alias, keystorePassword.toCharArray());
		if (key == null) {
			throw new KeyStoreException("No key found for alias: " + alias);
		}
		if (!(key instanceof PrivateKey)) {
			throw new KeyStoreException("Key under alias is not a PrivateKey: " + alias);
		}

		PrivateKey privateKey = (PrivateKey) key;
		PublicKey publicKey = ks.getCertificate(alias).getPublicKey();

		if (publicKey == null) {
			throw new KeyStoreException("No certificate/public key found for alias: " + alias);
		}

		System.out.println("✅ Loaded RSA key pair from keystore: " + keystorePath);
		return new KeyPair(publicKey, privateKey);
	}
}
