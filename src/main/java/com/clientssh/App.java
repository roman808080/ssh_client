package com.clientssh;

import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.io.resource.PathResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.util.io.output.SecureByteArrayOutputStream;
import org.apache.sshd.common.config.keys.writer.openssh.OpenSSHKeyPairResourceWriter;

import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.config.keys.DefaultAuthorizedKeysAuthenticator;

import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.shell.ProcessShellFactory;
import org.slf4j.impl.SimpleLogger;

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
    public static void main(String[] args) throws InterruptedException, IOException {
        System.setProperty(org.slf4j.impl.SimpleLogger.DEFAULT_LOG_LEVEL_KEY, "trace");

        SshServer sshd = SshServer.setUpDefaultServer();
        Path file = Path.of("testkeys/authorized_keys");
        PublickeyAuthenticator auth = new DefaultAuthorizedKeysAuthenticator(file, false);

        sshd.setPublickeyAuthenticator(auth);

        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(Path.of("key.ser")));
        // sshd.setShellFactory(new ProcessShellFactory(null, new String[] { "/bin/sh", "-i", "-l" }));
        sshd.setShellFactory(new ProcessShellFactory("/bin/sh", new String[] {"/bin/sh", "-i", "-l"}));

        sshd.setPort(2222);
        sshd.start();

        while (true) {
            Thread.sleep(1000);
        }
    }

    private static void workingWithEncryption() throws IOException, GeneralSecurityException {
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
