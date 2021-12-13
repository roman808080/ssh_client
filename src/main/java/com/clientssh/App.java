package com.clientssh;

import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.io.resource.PathResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.util.io.output.SecureByteArrayOutputStream;
import org.apache.sshd.common.config.keys.writer.openssh.OpenSSHKeyPairResourceWriter;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Arrays;
import java.io.ByteArrayOutputStream;

/**
 * Hello world!
 *
 */
public class App {
    public static void main(String[] args) throws IOException, GeneralSecurityException {
        Path pathToKey = Path.of("testkeys/id_ed25519");
        Path pathToDecryptedKey = Path.of("testkeys/java_id_ed25519_dec");

        try (
                InputStream inputStream = Files.newInputStream(pathToKey);
                ByteArrayOutputStream out = new SecureByteArrayOutputStream()) {

            KeyPair keyPair = SecurityUtils.loadKeyPairIdentities(null,
                    new PathResource(pathToKey), inputStream, FilePasswordProvider.of("test")).iterator().next();

            OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(keyPair, "decrypted by java", null, out);
            writeToFile(pathToDecryptedKey, out.toByteArray());
        }
    }

    private static void writeToFile(Path file, byte[] sensitiveData)
            throws IOException {
        try (ByteChannel out = Files.newByteChannel(file,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            ByteBuffer buf = ByteBuffer.wrap(sensitiveData);
            while (buf.hasRemaining()) {
                out.write(buf);
            }
        } finally {
            Arrays.fill(sensitiveData, (byte) 0);
        }
    }
}
