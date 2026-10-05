package de.soderer.network.trustmanager;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Proxy;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import de.soderer.network.HttpUtilities;
import de.soderer.network.NetworkUtilities;

/**
 * Helper methods to create trust managers and read truststores.
 */
public class TrustManagerUtilities {
	/**
	 * Utility class, not to be instantiated.
	 */
	private TrustManagerUtilities() {
	}

	/**
	 * Returns the trust managers of the system's default truststore.
	 *
	 * @return the trust managers
	 * @throws Exception
	 *             if the default truststore cannot be loaded
	 */
	public static TrustManager[] getDefaultTrustManagers() throws Exception {
		final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

		// Init the TrustmanagerFactory with systems default trust store.
		trustManagerFactory.init((KeyStore) null);

		return trustManagerFactory.getTrustManagers();
	}

	/**
	 * Returns the X509 trust manager of the system's default truststore.
	 *
	 * @return the trust manager
	 * @throws Exception
	 *             if the default truststore cannot be loaded
	 */
	public static X509TrustManager getDefaultTrustManager() throws Exception {
		final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

		// Init the TrustmanagerFactory with systems default trust store.
		tmf.init((KeyStore) null);

		for (final TrustManager tm : tmf.getTrustManagers()) {
			if (tm instanceof X509TrustManager) {
				return (X509TrustManager) tm;
			}
		}

		throw new IllegalStateException("No system default X509TrustManager found");
	}

	/**
	 * Creates a trust manager that accepts all certificates (insecure). Only use it to retrieve
	 * certificates or for connections that need no protection.
	 *
	 * @return the trust manager
	 */
	public static X509TrustManager createTrustAllTrustManager() {
		return new X509TrustManager() {
			@Override
			public X509Certificate[] getAcceptedIssuers() {
				// X509TrustManager contract requires a non-null array
				return new X509Certificate[0];
			}

			@Override
			public void checkClientTrusted(final X509Certificate[] certificates, final String authType) {
				// nothing to do
			}

			@Override
			public void checkServerTrusted(final X509Certificate[] certificates, final String authType) {
				// nothing to do
			}
		};
	}

	/**
	 * Reads a keystore without password. A keystore that appears empty is read again with an empty
	 * password.
	 *
	 * @param keystoreInputStream
	 *            the keystore data
	 * @return the keystore
	 * @throws Exception
	 *             if the keystore cannot be read
	 */
	public static KeyStore readKeyStore(final InputStream keystoreInputStream) throws Exception {
		return readKeyStore(keystoreInputStream, null);
	}

	/**
	 * Reads a keystore. Without password, a keystore that appears empty is read again with an empty
	 * password.
	 *
	 * @param keystoreInputStream
	 *            the keystore data
	 * @param keystorePassword
	 *            the password, null for none
	 * @return the keystore
	 * @throws Exception
	 *             if the keystore cannot be read
	 */
	public static KeyStore readKeyStore(final InputStream keystoreInputStream, final char[] keystorePassword) throws Exception {
		final java.io.ByteArrayOutputStream keystoreBuffer = new java.io.ByteArrayOutputStream();
		NetworkUtilities.copy(keystoreInputStream, keystoreBuffer);
		final byte[] keystoreBytes = keystoreBuffer.toByteArray();

		KeyStore trustedKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		try (InputStream firstAttemptStream = new ByteArrayInputStream(keystoreBytes)) {
			trustedKeyStore.load(firstAttemptStream, keystorePassword);
		}
		if (trustedKeyStore.size() == 0 && keystorePassword == null) {
			trustedKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			try (InputStream retryStream = new ByteArrayInputStream(keystoreBytes)) {
				trustedKeyStore.load(retryStream, "".toCharArray());
			}
		}
		return trustedKeyStore;
	}

	/**
	 * Creates a trust manager that only trusts the certificates of a keystore without password.
	 *
	 * @param keystoreInputStream
	 *            the keystore data
	 * @return the trust manager
	 * @throws Exception
	 *             if the keystore cannot be read
	 */
	public static TrustManager createTrustManagerForKeyStore(final InputStream keystoreInputStream) throws Exception {
		return createTrustManagerForKeyStore(readKeyStore(keystoreInputStream, null));
	}

	/**
	 * Creates a trust manager that only trusts the certificates of a keystore.
	 *
	 * @param keystoreInputStream
	 *            the keystore data
	 * @param keystorePassword
	 *            the password, null for none
	 * @return the trust manager
	 * @throws Exception
	 *             if the keystore cannot be read
	 */
	public static TrustManager createTrustManagerForKeyStore(final InputStream keystoreInputStream, final char[] keystorePassword) throws Exception {
		return createTrustManagerForKeyStore(readKeyStore(keystoreInputStream, keystorePassword));
	}

	/**
	 * Reads a keystore file without password, see {@link #readKeyStore(InputStream)}.
	 *
	 * @param keystoreFile
	 *            the keystore file
	 * @return the keystore
	 * @throws Exception
	 *             if the keystore cannot be read
	 */
	public static KeyStore readKeyStore(final File keystoreFile) throws Exception {
		return readKeyStore(keystoreFile, null);
	}

	/**
	 * Reads a keystore file, see {@link #readKeyStore(InputStream, char[])}.
	 *
	 * @param keystoreFile
	 *            the keystore file
	 * @param keystorePassword
	 *            the password, null for none
	 * @return the keystore
	 * @throws Exception
	 *             if the keystore cannot be read
	 */
	public static KeyStore readKeyStore(final File keystoreFile, final char[] keystorePassword) throws Exception {
		KeyStore trustedKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		try (FileInputStream myKeys = new FileInputStream(keystoreFile)) {
			trustedKeyStore.load(myKeys, keystorePassword);
		}
		if (trustedKeyStore.size() == 0 && keystorePassword == null) {
			trustedKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			try (FileInputStream myKeys = new FileInputStream(keystoreFile)) {
				trustedKeyStore.load(myKeys, "".toCharArray());
			}
		}
		return trustedKeyStore;
	}

	/**
	 * Creates a trust manager that only trusts the certificates of a keystore without password.
	 *
	 * @param keystoreFile
	 *            the keystore file
	 * @return the trust manager
	 * @throws Exception
	 *             if the keystore cannot be read
	 */
	public static TrustManager createTrustManagerForKeyStore(final File keystoreFile) throws Exception {
		return createTrustManagerForKeyStore(readKeyStore(keystoreFile, null));
	}

	/**
	 * Creates a trust manager that only trusts the certificates of a keystore.
	 *
	 * @param keystoreFile
	 *            the keystore file
	 * @param keystorePassword
	 *            the password, null for none
	 * @return the trust manager
	 * @throws Exception
	 *             if the keystore cannot be read
	 */
	public static TrustManager createTrustManagerForKeyStore(final File keystoreFile, final char[] keystorePassword) throws Exception {
		return createTrustManagerForKeyStore(readKeyStore(keystoreFile, keystorePassword));
	}

	/**
	 * Override systems default trusted keystore and define a trusted keystore to be used as single
	 * trusted keystore for certificate checks.
	 * <pre>
	 * SSLContext sslContext = SSLContext.getInstance("TLS");
	 * sslContext.init(null, new TrustManager[] { createTrustManagerForKeyStore(myOnlyTrustedKeyStore) }, null);
	 * SSLContext.setDefault(sslContext);
	 * </pre>
	 *
	 * @param trustedKeyStore
	 *            the trusted certificates
	 * @return the trust manager
	 * @throws Exception
	 *             if no trust manager can be created
	 */
	public static TrustManager createTrustManagerForKeyStore(final KeyStore trustedKeyStore) throws Exception {
		final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trustManagerFactory.init(trustedKeyStore);

		for (final TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
			if (trustManager instanceof X509TrustManager) {
				return trustManager;
			}
		}

		throw new Exception("Cannot create TrustManager");
	}

	/**
	 * Retrieves the TLS certificate of a server without checking it, and saves it in a new
	 * truststore file, e.g. to trust a self-signed certificate later.
	 *
	 * @param hostnameOrIpAndPort
	 *            the host with optional port, e.g. "example.com:8443" or "[::1]:8443"
	 * @param defaultPort
	 *            the port if none is given
	 * @param trustStoreFile
	 *            the truststore file to create
	 * @param trustStorePassword
	 *            the truststore password, null for none
	 * @param proxy
	 *            the proxy, null for a direct connection
	 * @throws Exception
	 *             if the file already exists, the port is invalid, or the certificate cannot be
	 *             retrieved or saved
	 */
	public static void createTrustStoreFile(final String hostnameOrIpAndPort, final int defaultPort, final File trustStoreFile, final char[] trustStorePassword, final Proxy proxy) throws Exception {
		if (trustStoreFile.exists()) {
			throw new Exception("File '" + trustStoreFile.getAbsolutePath() + "' already exists");
		}

		final String hostnameOrIp;
		final int port;
		if (hostnameOrIpAndPort.startsWith("[")) {
			// Bracketed IPv6 address, e.g. "[2001:db8::1]:8443" or "[::1]" - the brackets are what
			// RFC 3986 uses to unambiguously combine an IPv6 address (which itself contains colons)
			// with a trailing ":port", so this must be checked before the plain colon-split below.
			final int closingBracketIndex = hostnameOrIpAndPort.indexOf(']');
			if (closingBracketIndex < 0) {
				throw new Exception("Invalid host: missing closing ']' for bracketed IPv6 address: " + hostnameOrIpAndPort);
			}
			hostnameOrIp = hostnameOrIpAndPort.substring(1, closingBracketIndex);
			final String remainder = hostnameOrIpAndPort.substring(closingBracketIndex + 1);
			if (remainder.startsWith(":")) {
				try {
					port = Integer.parseInt(remainder.substring(1));
				} catch (@SuppressWarnings("unused") final Exception e) {
					throw new Exception("Invalid port: " + remainder.substring(1));
				}
			} else {
				port = defaultPort;
			}
		} else {
			final String[] hostParts = hostnameOrIpAndPort.split(":");
			if (hostParts.length == 2) {
				hostnameOrIp = hostParts[0];
				try {
					port = Integer.parseInt(hostParts[1]);
				} catch (@SuppressWarnings("unused") final Exception e) {
					throw new Exception("Invalid port: " + hostParts[1]);
				}
			} else {
				// Either a bare hostname, or an unbracketed IPv6 address (which may contain many
				// colons of its own, making a ":port" suffix ambiguous without brackets - per
				// RFC 3986 that requires the bracket notation above). Treat it as the bare host.
				hostnameOrIp = hostnameOrIpAndPort;
				port = defaultPort;
			}
		}

		final X509Certificate certificate = HttpUtilities.getServerTlsCertificate(hostnameOrIp, port, proxy);
		if (certificate == null) {
			throw new Exception("Cannot get TLS certificate for '" + hostnameOrIp + ":" + port + "'");
		}

		final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(null);

		final char[] password = trustStorePassword == null ? new char[0] : trustStorePassword;
		keyStore.setCertificateEntry(hostnameOrIp, certificate);

		try (OutputStream javaKeyStoreOutputStream = new FileOutputStream(trustStoreFile)) {
			keyStore.store(javaKeyStoreOutputStream, password);
		}
	}
}
