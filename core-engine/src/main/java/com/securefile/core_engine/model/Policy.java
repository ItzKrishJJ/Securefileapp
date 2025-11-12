package com.securefile.core_engine.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class Policy {
    private String sensitivity;
    private boolean requireSignature;
    private double preferredCompression;
    private boolean compress;

    // getters/setters
    public String getSensitivity() { return sensitivity; }
    public void setSensitivity(String sensitivity) { this.sensitivity = sensitivity; }

    public boolean isRequireSignature() { return requireSignature; }
    public void setRequireSignature(boolean requireSignature) { this.requireSignature = requireSignature; }

    public double getPreferredCompression() { return preferredCompression; }
    public void setPreferredCompression(double preferredCompression) { this.preferredCompression = preferredCompression; }

    public boolean isCompress() { return compress; }
    public void setCompress(boolean compress) { this.compress = compress; }
}
