package de.soderer.utilities;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

/**
 * Shared test infrastructure: self-signed certificates generated once per JVM via the JDK's
 * keytool (no external dependencies), and local ephemeral-port HTTP/HTTPS servers.
 */
public final class TestTlsSupport {
	/** Password used for all generated keystores */
	public static final String PASSWORD = "changeit";

	private static File workDir;

	/** Keystore (PKCS12) with private key + certificate for "localhost" (SAN dns:localhost, ip:127.0.0.1) */
	private static File localhostKeystoreFile;
	private static File localhostPemFile;
	private static X509Certificate localhostCertificate;

	/** Keystore with private key + certificate for "other.test" without any subject alternative names */
	private static File otherKeystoreFile;
	private static File otherPemFile;
	private static X509Certificate otherCertificate;

	private TestTlsSupport() {
	}

	private static synchronized void init() throws Exception {
		if (workDir != null) {
			return;
		}
		final File dir = Files.createTempDirectory("soderer-network-tls-test").toFile();
		dir.deleteOnExit();

		localhostKeystoreFile = new File(dir, "localhost.p12");
		localhostPemFile = new File(dir, "localhost.pem");
		generateKeyPair(localhostKeystoreFile, "localhost", "CN=localhost", "san=dns:localhost,ip:127.0.0.1");
		exportCertificate(localhostKeystoreFile, "localhost", localhostPemFile);
		localhostCertificate = readPemCertificate(localhostPemFile);

		otherKeystoreFile = new File(dir, "other.p12");
		otherPemFile = new File(dir, "other.pem");
		generateKeyPair(otherKeystoreFile, "other", "CN=other.test", null);
		exportCertificate(otherKeystoreFile, "other", otherPemFile);
		otherCertificate = readPemCertificate(otherPemFile);

		for (final File file : new File[] { localhostKeystoreFile, localhostPemFile, otherKeystoreFile, otherPemFile }) {
			file.deleteOnExit();
		}
		workDir = dir;
	}

	private static String keytoolPath() {
		final boolean isWindows = System.getProperty("os.name", "").toLowerCase().contains("windows");
		return System.getProperty("java.home") + File.separator + "bin" + File.separator + (isWindows ? "keytool.exe" : "keytool");
	}

	private static void generateKeyPair(final File keystoreFile, final String alias, final String dname, final String extension) throws Exception {
		if (extension == null) {
			runProcess(keytoolPath(), "-genkeypair", "-alias", alias, "-keyalg", "RSA", "-keysize", "2048", "-validity", "2",
					"-dname", dname, "-storetype", "PKCS12", "-keystore", keystoreFile.getAbsolutePath(), "-storepass", PASSWORD, "-keypass", PASSWORD);
		} else {
			runProcess(keytoolPath(), "-genkeypair", "-alias", alias, "-keyalg", "RSA", "-keysize", "2048", "-validity", "2",
					"-dname", dname, "-ext", extension, "-storetype", "PKCS12", "-keystore", keystoreFile.getAbsolutePath(), "-storepass", PASSWORD, "-keypass", PASSWORD);
		}
	}

	private static void exportCertificate(final File keystoreFile, final String alias, final File pemFile) throws Exception {
		runProcess(keytoolPath(), "-exportcert", "-alias", alias, "-keystore", keystoreFile.getAbsolutePath(), "-storepass", PASSWORD, "-rfc", "-file", pemFile.getAbsolutePath());
	}

	private static void runProcess(final String... command) throws Exception {
		final Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
		final String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
		final int exitCode = process.waitFor();
		if (exitCode != 0) {
			throw new IllegalStateException("Command failed with exit code " + exitCode + ": " + String.join(" ", command) + "\n" + output);
		}
	}

	/**
	 * Reads a single certificate from a PEM file.
	 *
	 * @param pemFile
	 *            the PEM file
	 * @return the certificate
	 * @throws Exception
	 *             if the file cannot be read
	 */
	public static X509Certificate readPemCertificate(final File pemFile) throws Exception {
		try (FileInputStream inputStream = new FileInputStream(pemFile)) {
			return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(inputStream);
		}
	}

	public static File getLocalhostKeystoreFile() throws Exception {
		init();
		return localhostKeystoreFile;
	}

	public static File getLocalhostPemFile() throws Exception {
		init();
		return localhostPemFile;
	}

	public static X509Certificate getLocalhostCertificate() throws Exception {
		init();
		return localhostCertificate;
	}

	public static File getOtherKeystoreFile() throws Exception {
		init();
		return otherKeystoreFile;
	}

	public static File getOtherPemFile() throws Exception {
		init();
		return otherPemFile;
	}

	public static X509Certificate getOtherCertificate() throws Exception {
		init();
		return otherCertificate;
	}

	/**
	 * Writes a truststore file (default keystore type) containing only trusted certificate entries.
	 *
	 * @param truststoreFile
	 *            the file to write
	 * @param password
	 *            the store password, may be empty
	 * @param certificates
	 *            the certificates to trust
	 * @return the written file
	 * @throws Exception
	 *             if the store cannot be written
	 */
	public static File writeTruststore(final File truststoreFile, final char[] password, final Certificate... certificates) throws Exception {
		final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(null, null);
		int index = 0;
		for (final Certificate certificate : certificates) {
			keyStore.setCertificateEntry("cert" + index++, certificate);
		}
		try (OutputStream outputStream = new FileOutputStream(truststoreFile)) {
			keyStore.store(outputStream, password);
		}
		return truststoreFile;
	}

	/**
	 * Creates an in-memory keystore with the given trusted certificates.
	 *
	 * @param certificates
	 *            the certificates
	 * @return the keystore
	 * @throws Exception
	 *             if the keystore cannot be created
	 */
	public static KeyStore createTrustKeyStore(final Certificate... certificates) throws Exception {
		final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(null, null);
		int index = 0;
		for (final Certificate certificate : certificates) {
			keyStore.setCertificateEntry("cert" + index++, certificate);
		}
		return keyStore;
	}

	/**
	 * Starts a local HTTP server on an ephemeral port.
	 *
	 * @param handler
	 *            the request handler for all paths
	 * @return the started server
	 * @throws IOException
	 *             if the server cannot be started
	 */
	public static HttpServer startHttpServer(final HttpHandler handler) throws IOException {
		final HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
		server.createContext("/", handler);
		server.setExecutor(null);
		server.start();
		return server;
	}

	/**
	 * Starts a local HTTPS server on an ephemeral port, using the localhost certificate.
	 *
	 * @param handler
	 *            the request handler for all paths
	 * @return the started server
	 * @throws Exception
	 *             if the server cannot be started
	 */
	public static HttpsServer startHttpsServer(final HttpHandler handler) throws Exception {
		return startHttpsServer(getLocalhostKeystoreFile(), handler);
	}

	/**
	 * Starts a local HTTPS server on an ephemeral port with the key of the given keystore.
	 *
	 * @param keystoreFile
	 *            PKCS12 keystore with the server key (password {@link #PASSWORD})
	 * @param handler
	 *            the request handler for all paths
	 * @return the started server
	 * @throws Exception
	 *             if the server cannot be started
	 */
	public static HttpsServer startHttpsServer(final File keystoreFile, final HttpHandler handler) throws Exception {
		init();
		final KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try (FileInputStream inputStream = new FileInputStream(keystoreFile)) {
			keyStore.load(inputStream, PASSWORD.toCharArray());
		}
		final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		keyManagerFactory.init(keyStore, PASSWORD.toCharArray());
		final SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

		final HttpsServer server = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
		server.setHttpsConfigurator(new HttpsConfigurator(sslContext));
		server.createContext("/", handler);
		server.setExecutor(null);
		server.start();
		return server;
	}

	/**
	 * Sends a complete response with the given body.
	 *
	 * @param exchange
	 *            the exchange
	 * @param statusCode
	 *            the HTTP status code
	 * @param body
	 *            the body text (UTF-8)
	 * @throws IOException
	 *             if writing fails
	 */
	public static void respond(final HttpExchange exchange, final int statusCode, final String body) throws IOException {
		final byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
		exchange.sendResponseHeaders(statusCode, bodyBytes.length == 0 ? -1 : bodyBytes.length);
		try (OutputStream responseBody = exchange.getResponseBody()) {
			responseBody.write(bodyBytes);
		}
	}
}
