package com.securefile.core_engine.controller;

import com.fasterxml.jackson.databind.DeserializationFeature;
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

import java.io.*;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

@RestController
@RequestMapping("/api/secure")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:3000")
public class SecurityController {

    private final CryptoService cryptoService;
    private final ObjectMapper mapper = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false); // ✅ ignore extra AI fields

    /** ✅ Generates random token for session tracking */
    private String generateToken() {
        byte[] tokenBytes = new byte[16];
        new SecureRandom().nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }

    /**
     * ✅ Encrypt uploaded files using hybrid PQC crypto (XChaCha20 + Kyber + Dilithium)
     */
    @PostMapping(value = "/encrypt", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> encryptFiles(
            @RequestPart("files") List<MultipartFile> files,
            @RequestPart(value = "policy", required = false) String policyJson,
            @RequestPart(value = "token", required = false) String providedToken // <-- frontend token
    ) {
        try {
            if (files == null || files.isEmpty()) {
                return ResponseEntity.badRequest().body("❌ No files uploaded.");
            }

            // Step 1️⃣: Zip files together
            byte[] zipped = ZipUtils.zipFiles(files);

            // Step 2️⃣: Parse AI policy safely
            Policy policy = null;
            if (policyJson != null && !policyJson.isBlank()) {
                policy = mapper.readValue(policyJson, Policy.class);
            }

            // Step 3️⃣: Use provided token (from frontend) or generate new one
            String sessionToken = (providedToken != null && !providedToken.isBlank())
                    ? providedToken
                    : generateToken();

            // Step 4️⃣: Encrypt via CryptoService
            List<String> filenames = files.stream().map(MultipartFile::getOriginalFilename).toList();
            HybridContainer container = cryptoService.hybridEncrypt(zipped, filenames, policy, sessionToken);

            // Step 5️⃣: Serialize & send encrypted result
            byte[] out = cryptoService.serializeContainer(container);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentDisposition(ContentDisposition.attachment().filename("securebundle.sfa").build());
            headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
            headers.add("X-Session-Token", sessionToken);

            return ResponseEntity.ok().headers(headers).body(out);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("❌ Encryption failed: " + e.getMessage());
        }
    }

    /**
     * ✅ Decrypt PQC container and return the recovered files as .zip
     */
    @PostMapping(value = "/decrypt", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> decryptFile(
            @RequestPart("file") MultipartFile file,
            @RequestPart(value = "token", required = false) String token
    ) {
        try {
            if (file == null || file.isEmpty()) {
                return ResponseEntity.badRequest().body("❌ No file provided for decryption.");
            }

            // Step 1️⃣: Deserialize hybrid container
            HybridContainer container = cryptoService.deserializeContainer(file.getBytes());

            // Step 2️⃣: Validate token match
            if (token != null && !cryptoService.verifyToken(container, token)) {
                System.out.println("❌ Invalid token provided: " + token);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or mismatched session token.");
            }

            // Step 3️⃣: Hybrid decryption
            byte[] decryptedZip = cryptoService.hybridDecrypt(container);

            // Step 4️⃣: Stream .zip result back to frontend
            InputStreamResource resource = new InputStreamResource(new ByteArrayInputStream(decryptedZip));

            HttpHeaders headers = new HttpHeaders();
            headers.setContentDisposition(ContentDisposition.attachment().filename("decrypted_bundle.zip").build());
            headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);

            return ResponseEntity.ok().headers(headers).body(resource);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("❌ Decryption failed: " + e.getMessage());
        }
    }
}
