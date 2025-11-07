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

@RestController
@RequestMapping("/api/security")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:3000")
public class SecurityController {

    private final CryptoService cryptoService;
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * ✅ Encrypt Multiple Files
     */
    @PostMapping(value = "/encrypt", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<InputStreamResource> encryptFiles(
            @RequestPart("files") List<MultipartFile> files,
            @RequestPart(value = "policy", required = false) String policyJson
    ) throws Exception {

        if (files == null || files.isEmpty()) {
            return ResponseEntity.badRequest().build();
        }

        // ✅ Zip all uploaded files
        byte[] zipped = ZipUtils.zipFiles(files);

        Policy policy = null;
        if (policyJson != null && !policyJson.isBlank()) {
            policy = mapper.readValue(policyJson, Policy.class);
        }

        List<String> fileNames = files.stream()
                .map(MultipartFile::getOriginalFilename)
                .toList();

        HybridContainer container = cryptoService.hybridEncrypt(zipped, fileNames, policy);

        byte[] out = cryptoService.serializeContainer(container);
        InputStreamResource resource = new InputStreamResource(new ByteArrayInputStream(out));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentDisposition(ContentDisposition.attachment()
                .filename("securebundle.sfa").build());
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);

        return new ResponseEntity<>(resource, headers, HttpStatus.OK);
    }

    /**
     * ✅ Decrypt .sfa → returns original ZIP
     */
    @PostMapping(value = "/decrypt", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<InputStreamResource> decryptFile(
            @RequestPart("file") MultipartFile containerFile
    ) throws Exception {

        byte[] bytes = containerFile.getBytes();
        HybridContainer container = cryptoService.deserializeContainer(bytes);
        byte[] zipBytes = cryptoService.hybridDecrypt(container);

        InputStreamResource resource = new InputStreamResource(new ByteArrayInputStream(zipBytes));
        HttpHeaders headers = new HttpHeaders();
        headers.setContentDisposition(ContentDisposition.attachment()
                .filename("decrypted.zip").build());
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);

        return new ResponseEntity<>(resource, headers, HttpStatus.OK);
    }
}
