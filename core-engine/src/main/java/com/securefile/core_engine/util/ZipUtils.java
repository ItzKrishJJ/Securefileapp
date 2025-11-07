package com.securefile.core_engine.util;

import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class ZipUtils {

    /**
     * ✅ Zip a list of MultipartFile into a single ZIP byte array.
     * Preserves original file names.
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
     * ✅ Zip a single MultipartFile into a ZIP byte array.
     * Used when only one file is uploaded.
     */
    public static byte[] zipSingleFile(MultipartFile file) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            ZipEntry entry = new ZipEntry(file.getOriginalFilename());
            zos.putNextEntry(entry);
            zos.write(file.getBytes());
            zos.closeEntry();
        }
        return baos.toByteArray();
    }

    /**
     * ✅ Zip a single raw byte array with a custom filename.
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
}
