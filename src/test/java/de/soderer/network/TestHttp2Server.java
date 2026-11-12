package de.soderer.network;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/**
 * Minimal local HTTP/2 test server without external dependencies (the JDK only contains an HTTP/2
 * client, no server).
 * <p>
 * Supports HTTP/2 via TLS with ALPN ("h2"), HTTP/2 via cleartext upgrade ("h2c") and plain HTTP/1.1,
 * so that the fallback of a requested HTTP/2 to HTTP/1.1 can be tested by disabling HTTP/2.
 * </p>
 * <p>
 * Only what the tests need is implemented: request headers sent via HTTP/2 are not decoded (HPACK
 * with Huffman coding), so for requests received via "h2" method and path are null. For "h2c" and
 * "http/1.1" they are taken from the HTTP/1.1 request line. Response headers are HPACK encoded as
 * literals without Huffman coding.
 * </p>
 */
public final class TestHttp2Server implements AutoCloseable {
	/** Protocol of a request received via HTTP/2 over TLS (ALPN) */
	public static final String PROTOCOL_H2 = "h2";
	/** Protocol of a request received via HTTP/2 after a cleartext upgrade */
	public static final String PROTOCOL_H2C = "h2c";
	/** Protocol of a request received via HTTP/1.1 */
	public static final String PROTOCOL_HTTP_1_1 = "http/1.1";

	private static final byte[] CLIENT_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(StandardCharsets.US_ASCII);

	private static final int FRAME_DATA = 0x0;
	private static final int FRAME_HEADERS = 0x1;
	private static final int FRAME_SETTINGS = 0x4;
	private static final int FRAME_PING = 0x6;
	private static final int FRAME_GOAWAY = 0x7;

	private static final int FLAG_END_STREAM = 0x1;
	private static final int FLAG_ACK = 0x1;
	private static final int FLAG_END_HEADERS = 0x4;
	private static final int FLAG_PADDED = 0x8;

	private static final int MAX_FRAME_SIZE = 16384;

	/**
	 * A request as received by the server.
	 *
	 * @param protocol
	 *            {@link #PROTOCOL_H2}, {@link #PROTOCOL_H2C} or {@link #PROTOCOL_HTTP_1_1}
	 * @param method
	 *            the request method, null for {@link #PROTOCOL_H2}
	 * @param path
	 *            the request path with query, null for {@link #PROTOCOL_H2}
	 * @param body
	 *            the request body, empty if none
	 */
	public record Request(String protocol, String method, String path, byte[] body) {
		public String bodyAsString() {
			return new String(body, StandardCharsets.UTF_8);
		}
	}

	/**
	 * A response to send.
	 *
	 * @param status
	 *            the HTTP status code
	 * @param headers
	 *            additional response headers
	 * @param body
	 *            the body text (UTF-8)
	 */
	public record Response(int status, Map<String, String> headers, String body) {
		public Response(final int status, final String body) {
			this(status, Map.of("Content-Type", "text/plain; charset=UTF-8"), body);
		}
	}

	private final ServerSocket serverSocket;
	private final boolean tls;
	private final boolean http2Enabled;
	private final Function<Request, Response> handler;
	private final List<Request> receivedRequests = new CopyOnWriteArrayList<>();
	private final List<Throwable> errors = new CopyOnWriteArrayList<>();
	private volatile boolean closed = false;

	private TestHttp2Server(final ServerSocket serverSocket, final boolean tls, final boolean http2Enabled, final Function<Request, Response> handler) {
		this.serverSocket = serverSocket;
		this.tls = tls;
		this.http2Enabled = http2Enabled;
		this.handler = handler;
		final Thread acceptThread = new Thread(this::acceptLoop, "TestHttp2Server-accept");
		acceptThread.setDaemon(true);
		acceptThread.start();
	}

	/**
	 * Starts a cleartext server ("http://").
	 *
	 * @param http2Enabled
	 *            true to accept an "h2c" upgrade, false for an HTTP/1.1 only server
	 * @param handler
	 *            creates the response for each request
	 * @return the started server
	 * @throws IOException
	 *             if the server cannot be started
	 */
	public static TestHttp2Server startCleartext(final boolean http2Enabled, final Function<Request, Response> handler) throws IOException {
		return new TestHttp2Server(new ServerSocket(0, 50, InetAddress.getLoopbackAddress()), false, http2Enabled, handler);
	}

	/**
	 * Starts a TLS server ("https://") with the key of a PKCS12 keystore (password {@link TestTlsSupport#PASSWORD}).
	 *
	 * @param keystoreFile
	 *            the keystore with the server key
	 * @param http2Enabled
	 *            true to offer "h2" via ALPN, false for an HTTP/1.1 only server
	 * @param handler
	 *            creates the response for each request
	 * @return the started server
	 * @throws Exception
	 *             if the server cannot be started
	 */
	public static TestHttp2Server startTls(final java.io.File keystoreFile, final boolean http2Enabled, final Function<Request, Response> handler) throws Exception {
		final KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try (FileInputStream inputStream = new FileInputStream(keystoreFile)) {
			keyStore.load(inputStream, TestTlsSupport.PASSWORD.toCharArray());
		}
		final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		keyManagerFactory.init(keyStore, TestTlsSupport.PASSWORD.toCharArray());
		final SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

		final SSLServerSocket sslServerSocket = (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket(0, 50, InetAddress.getLoopbackAddress());
		final SSLParameters sslParameters = sslServerSocket.getSSLParameters();
		sslParameters.setApplicationProtocols(http2Enabled ? new String[] { "h2", "http/1.1" } : new String[] { "http/1.1" });
		sslServerSocket.setSSLParameters(sslParameters);
		return new TestHttp2Server(sslServerSocket, true, http2Enabled, handler);
	}

	/**
	 * Returns the base URL of the server with "localhost" as host, e.g. "https://localhost:12345".
	 *
	 * @return the base URL without trailing slash
	 */
	public String getBaseUrl() {
		return (tls ? "https" : "http") + "://localhost:" + serverSocket.getLocalPort();
	}

	/**
	 * Returns all requests received so far.
	 *
	 * @return the requests in order of arrival
	 */
	public List<Request> getReceivedRequests() {
		return receivedRequests;
	}

	/**
	 * Returns errors of the server side, e.g. protocol violations of the client.
	 *
	 * @return the errors, empty if none
	 */
	public List<Throwable> getErrors() {
		return errors;
	}

	@Override
	public void close() {
		closed = true;
		try {
			serverSocket.close();
		} catch (@SuppressWarnings("unused") final IOException e) {
			// Do nothing
		}
	}

	private void acceptLoop() {
		while (!closed) {
			try {
				final Socket socket = serverSocket.accept();
				final Thread connectionThread = new Thread(() -> handleConnection(socket), "TestHttp2Server-connection");
				connectionThread.setDaemon(true);
				connectionThread.start();
			} catch (final IOException e) {
				if (!closed) {
					errors.add(e);
				}
			}
		}
	}

	private void handleConnection(final Socket socket) {
		try (socket) {
			socket.setSoTimeout(30000);
			final InputStream inputStream = new BufferedInputStream(socket.getInputStream());
			final OutputStream outputStream = socket.getOutputStream();

			if (tls) {
				final SSLSocket sslSocket = (SSLSocket) socket;
				sslSocket.startHandshake();
				if ("h2".equals(sslSocket.getApplicationProtocol())) {
					writeFrame(outputStream, FRAME_SETTINGS, 0, 0, new byte[0]);
					readClientPreface(inputStream);
					frameLoop(inputStream, outputStream, -1);
					return;
				}
			}

			final Http11Request http11Request = readHttp11Request(inputStream);
			final String upgrade = http11Request.headers.get("upgrade");
			if (!tls && http2Enabled && upgrade != null && upgrade.toLowerCase(Locale.ROOT).contains("h2c")) {
				outputStream.write("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
				writeFrame(outputStream, FRAME_SETTINGS, 0, 0, new byte[0]);
				outputStream.flush();
				readClientPreface(inputStream);
				// The upgraded request is answered on stream 1 (RFC 7540 3.2)
				final Request request = new Request(PROTOCOL_H2C, http11Request.method, http11Request.path, http11Request.body);
				receivedRequests.add(request);
				writeHttp2Response(outputStream, 1, handler.apply(request));
				frameLoop(inputStream, outputStream, 1);
			} else {
				final Request request = new Request(PROTOCOL_HTTP_1_1, http11Request.method, http11Request.path, http11Request.body);
				receivedRequests.add(request);
				writeHttp11Response(outputStream, handler.apply(request));
			}
		} catch (@SuppressWarnings("unused") final EOFException | java.net.SocketException | javax.net.ssl.SSLException e) {
			// Client closed the connection, or rejected the server certificate during the handshake
		} catch (final Throwable e) {
			if (!closed) {
				errors.add(e);
			}
		}
	}

	private void frameLoop(final InputStream inputStream, final OutputStream outputStream, final int alreadyAnsweredStreamId) throws IOException {
		final Map<Integer, ByteArrayOutputStream> requestBodies = new HashMap<>();
		while (true) {
			final byte[] frameHeader = readExactly(inputStream, 9);
			final int length = ((frameHeader[0] & 0xFF) << 16) | ((frameHeader[1] & 0xFF) << 8) | (frameHeader[2] & 0xFF);
			final int type = frameHeader[3] & 0xFF;
			final int flags = frameHeader[4] & 0xFF;
			final int streamId = ((frameHeader[5] & 0x7F) << 24) | ((frameHeader[6] & 0xFF) << 16) | ((frameHeader[7] & 0xFF) << 8) | (frameHeader[8] & 0xFF);
			final byte[] payload = readExactly(inputStream, length);

			if (type == FRAME_SETTINGS && (flags & FLAG_ACK) == 0) {
				writeFrame(outputStream, FRAME_SETTINGS, FLAG_ACK, 0, new byte[0]);
			} else if (type == FRAME_PING && (flags & FLAG_ACK) == 0) {
				writeFrame(outputStream, FRAME_PING, FLAG_ACK, 0, payload);
			} else if (type == FRAME_GOAWAY) {
				return;
			} else if (type == FRAME_HEADERS && streamId != alreadyAnsweredStreamId) {
				requestBodies.put(streamId, new ByteArrayOutputStream());
				if ((flags & FLAG_END_STREAM) != 0) {
					answerHttp2Request(outputStream, streamId, requestBodies.remove(streamId));
				}
			} else if (type == FRAME_DATA && requestBodies.containsKey(streamId)) {
				int dataStart = 0;
				int dataLength = payload.length;
				if ((flags & FLAG_PADDED) != 0) {
					final int padLength = payload[0] & 0xFF;
					dataStart = 1;
					dataLength = payload.length - 1 - padLength;
				}
				requestBodies.get(streamId).write(payload, dataStart, dataLength);
				if ((flags & FLAG_END_STREAM) != 0) {
					answerHttp2Request(outputStream, streamId, requestBodies.remove(streamId));
				}
			}
			// All other frames (WINDOW_UPDATE, PRIORITY, RST_STREAM, CONTINUATION, ...) are ignored
		}
	}

	private void answerHttp2Request(final OutputStream outputStream, final int streamId, final ByteArrayOutputStream body) throws IOException {
		final Request request = new Request(PROTOCOL_H2, null, null, body.toByteArray());
		receivedRequests.add(request);
		writeHttp2Response(outputStream, streamId, handler.apply(request));
	}

	private static void readClientPreface(final InputStream inputStream) throws IOException {
		final byte[] preface = readExactly(inputStream, CLIENT_PREFACE.length);
		if (!Arrays.equals(CLIENT_PREFACE, preface)) {
			throw new IOException("Invalid HTTP/2 client preface");
		}
	}

	private static synchronized void writeFrame(final OutputStream outputStream, final int type, final int flags, final int streamId, final byte[] payload) throws IOException {
		final byte[] frameHeader = new byte[] {
				(byte) (payload.length >>> 16), (byte) (payload.length >>> 8), (byte) payload.length,
				(byte) type, (byte) flags,
				(byte) (streamId >>> 24), (byte) (streamId >>> 16), (byte) (streamId >>> 8), (byte) streamId };
		outputStream.write(frameHeader);
		outputStream.write(payload);
		outputStream.flush();
	}

	private static void writeHttp2Response(final OutputStream outputStream, final int streamId, final Response response) throws IOException {
		final ByteArrayOutputStream headerBlock = new ByteArrayOutputStream();
		if (response.status() == 200) {
			// Indexed header field, static table index 8 = ":status: 200"
			headerBlock.write(0x88);
		} else {
			// Literal header field without indexing, indexed name (static table index 8 = ":status")
			writeHpackInteger(headerBlock, 4, 0x00, 8);
			writeHpackString(headerBlock, Integer.toString(response.status()));
		}
		for (final Map.Entry<String, String> header : response.headers().entrySet()) {
			// Literal header field without indexing, new name. HTTP/2 header names must be lower case.
			headerBlock.write(0x00);
			writeHpackString(headerBlock, header.getKey().toLowerCase(Locale.ROOT));
			writeHpackString(headerBlock, header.getValue());
		}

		final byte[] body = response.body() == null ? new byte[0] : response.body().getBytes(StandardCharsets.UTF_8);
		writeFrame(outputStream, FRAME_HEADERS, FLAG_END_HEADERS | (body.length == 0 ? FLAG_END_STREAM : 0), streamId, headerBlock.toByteArray());
		for (int offset = 0; offset < body.length; offset += MAX_FRAME_SIZE) {
			final int end = Math.min(body.length, offset + MAX_FRAME_SIZE);
			writeFrame(outputStream, FRAME_DATA, end == body.length ? FLAG_END_STREAM : 0, streamId, Arrays.copyOfRange(body, offset, end));
		}
	}

	private static void writeHpackInteger(final ByteArrayOutputStream output, final int prefixBits, final int firstByteFlags, final int value) {
		final int maxPrefixValue = (1 << prefixBits) - 1;
		if (value < maxPrefixValue) {
			output.write(firstByteFlags | value);
		} else {
			output.write(firstByteFlags | maxPrefixValue);
			int remaining = value - maxPrefixValue;
			while (remaining >= 128) {
				output.write((remaining & 0x7F) | 0x80);
				remaining >>>= 7;
			}
			output.write(remaining);
		}
	}

	private static void writeHpackString(final ByteArrayOutputStream output, final String value) {
		final byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
		// No Huffman coding (H bit 0)
		writeHpackInteger(output, 7, 0x00, bytes.length);
		output.write(bytes, 0, bytes.length);
	}

	private static void writeHttp11Response(final OutputStream outputStream, final Response response) throws IOException {
		final byte[] body = response.body() == null ? new byte[0] : response.body().getBytes(StandardCharsets.UTF_8);
		final StringBuilder head = new StringBuilder();
		head.append("HTTP/1.1 ").append(response.status()).append(' ').append(HttpUtilities.getHttpStatusText(response.status())).append("\r\n");
		for (final Map.Entry<String, String> header : response.headers().entrySet()) {
			head.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
		}
		head.append("Content-Length: ").append(body.length).append("\r\n");
		head.append("Connection: close\r\n\r\n");
		outputStream.write(head.toString().getBytes(StandardCharsets.ISO_8859_1));
		outputStream.write(body);
		outputStream.flush();
	}

	private static final class Http11Request {
		private String method;
		private String path;
		private final Map<String, String> headers = new LinkedHashMap<>();
		private byte[] body = new byte[0];
	}

	private static Http11Request readHttp11Request(final InputStream inputStream) throws IOException {
		final Http11Request request = new Http11Request();
		final String requestLine = readLine(inputStream);
		final String[] requestLineParts = requestLine.split(" ");
		if (requestLineParts.length != 3) {
			throw new IOException("Invalid request line: " + requestLine);
		}
		request.method = requestLineParts[0];
		request.path = requestLineParts[1];
		String headerLine;
		while (!(headerLine = readLine(inputStream)).isEmpty()) {
			final int colonIndex = headerLine.indexOf(':');
			if (colonIndex > 0) {
				request.headers.put(headerLine.substring(0, colonIndex).trim().toLowerCase(Locale.ROOT), headerLine.substring(colonIndex + 1).trim());
			}
		}

		final String transferEncoding = request.headers.get("transfer-encoding");
		if (transferEncoding != null && transferEncoding.toLowerCase(Locale.ROOT).contains("chunked")) {
			final ByteArrayOutputStream body = new ByteArrayOutputStream();
			while (true) {
				final int chunkSize = Integer.parseInt(readLine(inputStream).split(";")[0].trim(), 16);
				if (chunkSize == 0) {
					while (!readLine(inputStream).isEmpty()) {
						// Ignore trailers
					}
					break;
				}
				body.write(readExactly(inputStream, chunkSize));
				readLine(inputStream);
			}
			request.body = body.toByteArray();
		} else if (request.headers.containsKey("content-length")) {
			final int contentLength = Integer.parseInt(request.headers.get("content-length"));
			request.body = readExactly(inputStream, contentLength);
		}
		return request;
	}

	/**
	 * Reads exactly the given number of bytes. The stream is not wrapped (e.g. in a DataInputStream),
	 * because such a wrapper would have to be closed, which would also close the socket stream.
	 */
	private static byte[] readExactly(final InputStream inputStream, final int length) throws IOException {
		final byte[] data = inputStream.readNBytes(length);
		if (data.length < length) {
			throw new EOFException("Unexpected end of stream, expected " + length + " bytes but got " + data.length);
		}
		return data;
	}

	private static String readLine(final InputStream inputStream) throws IOException {
		final ByteArrayOutputStream line = new ByteArrayOutputStream();
		int previous = -1;
		while (true) {
			final int current = inputStream.read();
			if (current == -1) {
				throw new EOFException("Unexpected end of stream");
			}
			if (previous == '\r' && current == '\n') {
				final byte[] lineBytes = line.toByteArray();
				return new String(lineBytes, 0, lineBytes.length - 1, StandardCharsets.ISO_8859_1);
			}
			line.write(current);
			previous = current;
		}
	}
}
