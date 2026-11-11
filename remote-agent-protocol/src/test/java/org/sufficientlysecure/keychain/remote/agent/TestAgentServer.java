package org.sufficientlysecure.keychain.remote.agent;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.FilterInputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Integration fixture only: forwards cryptography to a throwaway reference agent
 * so a real gpg process can exercise our protocol. No production code depends
 * on this class or its desktop-only APIs.
 */
public final class TestAgentServer {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) { throw new IllegalArgumentException("reference-home keygrip unix-path|tcp:port"); }
        ReferenceBackend backend = new ReferenceBackend(args[0], args[1]);
        ServerSocketChannel server;
        if (args[2].startsWith("tcp:")) {
            server = ServerSocketChannel.open();
            server.bind(new InetSocketAddress("127.0.0.1", Integer.parseInt(args[2].substring(4))));
        } else {
            server = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
            server.bind(UnixDomainSocketAddress.of(args[2]));
        }
        System.out.println("READY " + server.getLocalAddress());
        System.out.flush();
        while (true) {
            final SocketChannel client = server.accept();
            Thread worker = new Thread(() -> {
                try (SocketChannel connection = client) {
                    InputStream trace = new FilterInputStream(Channels.newInputStream(connection)) {
                        final ByteArrayOutputStream line = new ByteArrayOutputStream();
                        public int read() throws IOException {
                            int b = super.read();
                            if (b == '\n') {
                                String command = new String(line.toByteArray(), StandardCharsets.UTF_8);
                                System.err.println("COMMAND " + command);
                                line.reset();
                            } else if (b >= 0) { line.write(b); }
                            return b;
                        }
                    };
                    new AssuanSession(backend).serve(trace, Channels.newOutputStream(connection));
                } catch (IOException e) { e.printStackTrace(System.err); }
            });
            worker.setDaemon(true);
            worker.start();
        }
    }

    private static final class ReferenceBackend implements AgentBackend {
        final String home;
        final AgentKey key;

        ReferenceBackend(String home, String grip) throws Exception {
            this.home = home;
            key = new AgentKey(grip, query("READKEY " + grip), "fixture");
        }

        public List<AgentKey> getKeys() { return Collections.singletonList(key); }

        public byte[] sign(AgentKey key, int algorithm, byte[] digest, String description) throws AgentException {
            StringBuilder hex = new StringBuilder();
            for (byte b : digest) { hex.append(String.format("%02X", b & 255)); }
            return query("SIGKEY " + key.getKeygrip(), "SETHASH " + algorithm + " " + hex, "PKSIGN");
        }

        private byte[] query(String... commands) throws AgentException {
            List<String> command = new ArrayList<>();
            Collections.addAll(command, "gpg-connect-agent", "--homedir", home);
            Collections.addAll(command, commands);
            command.add("/bye");
            try {
                Process process = new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.INHERIT).start();
                byte[] response = process.getInputStream().readAllBytes();
                if (process.waitFor() != 0) { throw new IOException("Reference process failed"); }
                ByteArrayOutputStream data = new ByteArrayOutputStream();
                int offset = 0;
                for (int i = 0; i < response.length; i++) {
                    if (response[i] != '\n') { continue; }
                    if (i - offset >= 4 && response[offset] == 'E' && response[offset + 1] == 'R') {
                        throw new IOException("Reference agent rejected request");
                    }
                    if (i - offset >= 2 && response[offset] == 'D' && response[offset + 1] == ' ') {
                        for (int p = offset + 2; p < i; p++) {
                            if (response[p] == '%') {
                                data.write(Character.digit((char) response[++p], 16) * 16
                                        + Character.digit((char) response[++p], 16));
                            } else { data.write(response[p]); }
                        }
                    }
                    offset = i + 1;
                }
                return data.toByteArray();
            } catch (IOException | InterruptedException e) {
                throw new AgentException(AgentException.GENERAL, "Reference fixture failed");
            }
        }
    }
}
