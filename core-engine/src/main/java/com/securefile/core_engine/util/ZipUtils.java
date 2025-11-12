package com.securefile.core_engine.util;

import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.file.*;
import java.util.List;
import java.util.zip.*;

/**
 * Utility class providing methods for compressing and decompressing files.
 *
 * <p>Used by the SecureFile Core Engine for:
 * <ul>
 *   <li>Zipping multiple uploaded files into a single archive before encryption</li>
 *   <li>Unzipping decrypted data back to a temporary folder</li>
 *   <li>Zipping directories after decryption for convenient download</li>
 * </ul>
 * </p>
 */
public class ZipUtils {

    private static final int BUFFER_SIZE = 4096;

    /**
     * Compress multiple uploaded MultipartFiles into a single ZIP archive.
     *
     * @param files list of multipart files to zip
     * @return byte[] containing the zipped data
     */
    public static byte[] zipFiles(List<MultipartFile> files) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            for (MultipartFile file : files) {
                ZipEntry entry = new ZipEntry(file.getOriginalFilename());
                zos.putNextEntry(entry);
                zos.write(file.getBytes());
                zos.closeEntry();
            }
        }
        return baos.toByteArray();
    }

    /**
     * Create a ZIP archive from a single file.
     *
     * @param filename name of the file inside the ZIP
     * @param data file content as bytes
     * @return zipped byte array
     */
    public static byte[] zipSingle(String filename, byte[] data) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            ZipEntry entry = new ZipEntry(filename);
            zos.putNextEntry(entry);
            zos.write(data);
            zos.closeEntry();
        }
        return baos.toByteArray();
    }

    /**
     * Unzips a byte array containing a ZIP archive into a temporary directory.
     *
     * @param zipData compressed ZIP data
     * @return File object representing the extracted temporary directory
     */
    public static File unzipToTempDir(byte[] zipData) throws IOException {
        Path tempDir = Files.createTempDirectory("securefile_unzip_");

        try (ByteArrayInputStream bais = new ByteArrayInputStream(zipData);
             ZipInputStream zis = new ZipInputStream(bais)) {

            ZipEntry entry;
            byte[] buffer = new byte[BUFFER_SIZE];

            while ((entry = zis.getNextEntry()) != null) {
                Path filePath = tempDir.resolve(entry.getName());
                if (entry.isDirectory()) {
                    Files.createDirectories(filePath);
                } else {
                    Files.createDirectories(filePath.getParent());
                    try (FileOutputStream fos = new FileOutputStream(filePath.toFile())) {
                        int len;
                        while ((len = zis.read(buffer)) > 0) {
                            fos.write(buffer, 0, len); // ✅ fixed here
                        }
                    }
                }
                zis.closeEntry();
            }
        }

        return tempDir.toFile();
    }


    /**
     * Recursively compresses a directory into a single ZIP archive.
     *
     * @param directory directory to zip
     * @return byte[] ZIP data of the directory contents
     */
    public static byte[] zipDirectory(File directory) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            Path basePath = directory.toPath();
            Files.walk(basePath)
                    .filter(path -> !Files.isDirectory(path))
                    .forEach(path -> {
                        String relativePath = basePath.relativize(path).toString();
                        try (InputStream fis = Files.newInputStream(path)) {
                            ZipEntry entry = new ZipEntry(relativePath);
                            zos.putNextEntry(entry);

                            byte[] buffer = new byte[BUFFER_SIZE];
                            int len;
                            while ((len = fis.read(buffer)) > 0) {
                                zos.write(buffer, 0, len);
                            }
                            zos.closeEntry();
                        } catch (IOException e) {
                            throw new UncheckedIOException(e);
                        }
                    });
        }

        return baos.toByteArray();
    }
}
