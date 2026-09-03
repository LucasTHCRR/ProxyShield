package de.lucasthcr.bridgesave.proxyshield.storage;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

/**
 * A minimal Redis client speaking RESP over a plain socket.
 * <p>
 * ProxyShield needs six commands - {@code AUTH}, {@code SELECT}, {@code GET}, {@code SET},
 * {@code DEL} and pub/sub - and has to work identically on five server platforms, three of which
 * ship no shading-safe classpath of their own. Bundling a full client library means relocating it
 * and its transitive dependencies into every jar, where it can still collide with another plugin's
 * copy. RESP is a line protocol simple enough that speaking it directly is the smaller risk, the
 * same reasoning that gave this plugin its own JSON reader.
 * <p>
 * Not thread safe by itself: {@link RedisStorage} owns one instance per purpose and serialises
 * access to it.
 */
final class RedisClient implements AutoCloseable {

   private final String host;
   private final int port;
   private final String username;
   private final String password;
   private final int database;
   private final int timeoutMillis;

   private Socket socket;
   private BufferedInputStream in;
   private OutputStream out;

   RedisClient(String host, int port, String username, String password, int database,
         int timeoutMillis) {
      this.host = host;
      this.port = port;
      this.username = username == null || username.isBlank() ? null : username;
      this.password = password == null || password.isBlank() ? null : password;
      this.database = database;
      this.timeoutMillis = timeoutMillis;
   }

   /** Opens the connection, authenticating and selecting the database. */
   void connect() throws IOException {
      close();

      Socket fresh = new Socket();
      fresh.connect(new InetSocketAddress(host, port), timeoutMillis);
      fresh.setSoTimeout(timeoutMillis);
      fresh.setTcpNoDelay(true);
      this.socket = fresh;
      this.in = new BufferedInputStream(fresh.getInputStream());
      this.out = fresh.getOutputStream();

      if (password != null) {
         if (username != null) {
            expectOk(command("AUTH", username, password), "AUTH");
         } else {
            expectOk(command("AUTH", password), "AUTH");
         }
      }
      if (database > 0) {
         expectOk(command("SELECT", String.valueOf(database)), "SELECT");
      }
   }

   boolean isConnected() {
      Socket current = socket;
      return current != null && current.isConnected() && !current.isClosed();
   }

   /** Sends a command and reads one reply. Reconnects once if the connection went away. */
   Object command(String... args) throws IOException {
      if (!isConnected()) {
         connect();
      }
      try {
         write(args);
         return read();
      } catch (IOException broken) {
         // A pooled Redis connection is dropped after its idle timeout, which looks like this.
         connect();
         write(args);
         return read();
      }
   }

   String get(String key) throws IOException {
      Object reply = command("GET", key);
      return reply instanceof String text ? text : null;
   }

   /** {@code SET key value PX millis}. */
   void setWithExpiry(String key, String value, long ttlMillis) throws IOException {
      command("SET", key, value, "PX", String.valueOf(Math.max(1L, ttlMillis)));
   }

   void delete(String key) throws IOException {
      command("DEL", key);
   }

   void publish(String channel, String message) throws IOException {
      command("PUBLISH", channel, message);
   }

   /**
    * Subscribes and blocks, handing every message to {@code handler}.
    * <p>
    * A subscribed connection may not issue other commands, so the caller runs this on a dedicated
    * client and thread.
    */
   void subscribe(String channel, BiConsumer<String, String> handler) throws IOException {
      if (!isConnected()) {
         connect();
      }
      // No read timeout: a subscription is idle by design, and an idle read is not a failure.
      socket.setSoTimeout(0);
      write(new String[] {"SUBSCRIBE", channel});

      while (isConnected()) {
         Object reply = read();
         if (!(reply instanceof List<?> parts) || parts.size() < 3) {
            continue;
         }
         if ("message".equals(String.valueOf(parts.get(0)))) {
            handler.accept(String.valueOf(parts.get(1)), String.valueOf(parts.get(2)));
         }
      }
   }

   private void expectOk(Object reply, String what) throws IOException {
      if (reply instanceof RedisError error) {
         throw new IOException(what + " failed: " + error.message());
      }
   }

   // ---------------------------------------------------------------- protocol

   private void write(String[] args) throws IOException {
      StringBuilder command = new StringBuilder();
      command.append('*').append(args.length).append("\r\n");
      for (String arg : args) {
         byte[] raw = arg.getBytes(StandardCharsets.UTF_8);
         command.append('$').append(raw.length).append("\r\n").append(arg).append("\r\n");
      }
      out.write(command.toString().getBytes(StandardCharsets.UTF_8));
      out.flush();
   }

   /** Reads one reply: {@link String}, {@link Long}, {@link List}, {@link RedisError} or null. */
   private Object read() throws IOException {
      int marker = in.read();
      if (marker < 0) {
         throw new IOException("connection closed by the server");
      }

      return switch ((char) marker) {
         case '+' -> readLine();
         case '-' -> new RedisError(readLine());
         case ':' -> Long.parseLong(readLine());
         case '$' -> readBulk();
         case '*' -> readArray();
         default -> throw new IOException("unexpected reply type '" + (char) marker + "'");
      };
   }

   private String readLine() throws IOException {
      StringBuilder line = new StringBuilder();
      int c;
      while ((c = in.read()) >= 0) {
         if (c == '\r') {
            in.read();
            return line.toString();
         }
         line.append((char) c);
      }
      throw new IOException("connection closed mid-line");
   }

   private String readBulk() throws IOException {
      int length = Integer.parseInt(readLine());
      if (length < 0) {
         return null;
      }

      byte[] body = new byte[length];
      int read = 0;
      while (read < length) {
         int chunk = in.read(body, read, length - read);
         if (chunk < 0) {
            throw new IOException("connection closed mid-value");
         }
         read += chunk;
      }
      // Trailing CRLF.
      if (in.read() >= 0) {
         in.read();
      }
      return new String(body, StandardCharsets.UTF_8);
   }

   private List<Object> readArray() throws IOException {
      int count = Integer.parseInt(readLine());
      if (count < 0) {
         return List.of();
      }
      List<Object> items = new ArrayList<>(count);
      for (int i = 0; i < count; i++) {
         items.add(read());
      }
      return items;
   }

   @Override
   public void close() {
      InputStream stream = in;
      Socket current = socket;
      in = null;
      out = null;
      socket = null;
      try {
         if (stream != null) {
            stream.close();
         }
      } catch (IOException ignored) {
         // Closing a broken connection is allowed to fail.
      }
      try {
         if (current != null) {
            current.close();
         }
      } catch (IOException ignored) {
         // Same.
      }
   }

   /** An {@code -ERR ...} reply. */
   record RedisError(String message) {
   }
}
