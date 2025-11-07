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
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/security")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:3000")  // allow frontend
public class SecurityController {

    private final CryptoService cryptoService;
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Encrypt endpoint: receives one file + optional policy JSON.
     */
    @PostMapping(value = "/encrypt", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<InputStreamResource> encryptFile(
            @RequestPart("files") MultipartFile file, // ✅ changed name to match frontend
            @RequestPart(value = "policy", required = false) String policyJson
    ) throws Exception {

        // 1. Zip single file into a byte array
        byte[] zipped = ZipUtils.zipSingleFile(file);

        // 2. Parse policy (if present)
        Policy policy = null;
        if (policyJson != null && !policyJson.isBlank()) {
            policy = mapper.readValue(policyJson, Policy.class);
        }

        // 3. Encrypt file
        HybridContainer container = cryptoService.hybridEncrypt(zipped,
                List.of(file.getOriginalFilename()), policy);

        // 4. Serialize container and send as response
        byte[] out = cryptoService.serializeContainer(container);
        InputStreamResource resource = new InputStreamResource(new ByteArrayInputStream(out));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentDisposition(ContentDisposition.attachment()
                .filename(file.getOriginalFilename() + ".sfa").build());
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);

        return new ResponseEntity<>(resource, headers, HttpStatus.OK);
    }

    @PostMapping(value = "/decrypt", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<InputStreamResource> decryptFile(@RequestPart("file") MultipartFile containerFile) throws Exception {
        byte[] bytes = containerFile.getBytes();
        HybridContainer container = cryptoService.deserializeContainer(bytes);
        byte[] zipBytes = cryptoService.hybridDecrypt(container);

        InputStreamResource resource = new InputStreamResource(new ByteArrayInputStream(zipBytes));
        HttpHeaders headers = new HttpHeaders();
        headers.setContentDisposition(ContentDisposition.attachment().filename("decrypted.zip").build());
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);

        return new ResponseEntity<>(resource, headers, HttpStatus.OK);
    }
}
