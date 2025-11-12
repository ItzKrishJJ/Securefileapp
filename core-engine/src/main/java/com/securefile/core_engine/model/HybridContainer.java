package com.securefile.core_engine.model;

import java.util.List;

public class HybridContainer {
    private String encSymmetricKey; // base64
    private String nonce; // base64
    private String ciphertext; // base64
    private List<String> filenames;
    private Policy policy;
    private String token;

    // getters / setters
    public String getEncSymmetricKey() { return encSymmetricKey; }
    public void setEncSymmetricKey(String encSymmetricKey) { this.encSymmetricKey = encSymmetricKey; }
    public String getNonce() { return nonce; }
    public void setNonce(String nonce) { this.nonce = nonce; }
    public String getCiphertext() { return ciphertext; }
    public void setCiphertext(String ciphertext) { this.ciphertext = ciphertext; }
    public List<String> getFilenames() { return filenames; }
    public void setFilenames(List<String> filenames) { this.filenames = filenames; }
    public Policy getPolicy() { return policy; }
    public void setPolicy(Policy policy) { this.policy = policy; }
    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }
}
