package com.securefile.core_engine.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securefile.core_engine.model.HybridContainer;
import com.securefile.core_engine.model.Policy;
import com.securefile.core_engine.service.CryptoService;
import com.securefile.core_engine.util.ZipUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

@RestController
@RequestMapping("/api/security")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:3000")
public class SecurityController {

    private final CryptoService cryptoService;
    private final ObjectMapper mapper = new ObjectMapper();

    // ✅ Generate random token for encryption
    private String generateToken() {
        byte[] tokenBytes = new byte[16];
        new SecureRandom().nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }

    /**
     * ✅ Encrypt Multiple Files with token
     */
    @PostMapping(value = "/encrypt", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> encryptFiles(
            @RequestPart("files") List<MultipartFile> files,
            @RequestPart(value = "policy", required = false) String policyJson
    ) throws Exception {

        if (files == null || files.isEmpty()) {
            return ResponseEntity.badRequest().build();
        }

        byte[] zipped = ZipUtils.zipFiles(files);
        Policy policy = null;
        if (policyJson != null && !policyJson.isBlank()) {
            policy = mapper.readValue(policyJson, Policy.class);
        }

        List<String> fileNames = files.stream()
                .map(MultipartFile::getOriginalFilename)
                .toList();

        String encryptionToken = generateToken();

        HybridContainer container = cryptoService.hybridEncrypt(zipped, fileNames, policy, encryptionToken);

        byte[] out = cryptoService.serializeContainer(container);
        InputStreamResource resource = new InputStreamResource(new ByteArrayInputStream(out));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentDisposition(ContentDisposition.attachment()
                .filename("securebundle.sfa").build());
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        headers.add("X-Encryption-Token", encryptionToken); // ✅ Include token in response header

        return new ResponseEntity<>(resource, headers, HttpStatus.OK);
    }

    /**
     * ✅ Decrypt file with token validation
     */
    @PostMapping(value = "/decrypt", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> decryptFile(
            @RequestPart("file") MultipartFile containerFile,
            @RequestPart("token") String token
    ) throws Exception {

        byte[] bytes = containerFile.getBytes();
        HybridContainer container = cryptoService.deserializeContainer(bytes);

        if (!cryptoService.verifyToken(container, token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid or missing encryption token.");
        }

        byte[] zipBytes = cryptoService.hybridDecrypt(container);
        InputStreamResource resource = new InputStreamResource(new ByteArrayInputStream(zipBytes));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentDisposition(ContentDisposition.attachment()
                .filename("decrypted.zip").build());
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);

        return new ResponseEntity<>(resource, headers, HttpStatus.OK);
    }
}
