package com.securefile.core_engine.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Simple policy model that frontend can send to influence encryption behavior.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class Policy {
    private String sensitivity = "medium"; // low | medium | high
    private boolean requireSignature = true;
    private boolean compress = true;
    private String preferredCompression = "deflate"; // reserved for future use
}
