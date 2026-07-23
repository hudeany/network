package de.soderer.network.trustmanager;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * This TrustManager checks for a servers TLS certificate to be valid against the system default truststore.<br />
 * Afterwards it checks the given additional truststore.<br />
 * Default JVM truststore lies at ${java.home}/lib/security/cacerts<br />
 *<br />
 * Usage example:
 *
 * <pre>
 * TrustManager[] trustManagers = new TrustManager[] { new AdditionalTruststoreTrustManager("truststore.jks", "changeit".toCharArray()) };
 *
 * SSLContext context = SSLContext.getInstance("TLS");
 * context.init(null, trustManagers, new SecureRandom());
 *
 * URL url = new URL("https://example.com");
 * HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
 *
 * connection.setSSLSocketFactory(context.getSocketFactory());
 * connection.connect();
 *
 * System.out.println("Response: " + connection.getResponseCode());
 * </pre>
 */
public class AdditionalTruststoreTrustManager implements X509TrustManager {
	private final X509TrustManager systemDefaultTrustManager;
	private final X509TrustManager additionalTrustManager;

	public AdditionalTruststoreTrustManager(final File additionalTrustStoreFile, final char[] trustStorePassword) throws Exception {
		systemDefaultTrustManager = TrustManagerUtilities.getDefaultTrustManager();
		additionalTrustManager = createAdditionalTrustManager(additionalTrustStoreFile, trustStorePassword);
	}

	private static X509TrustManager createAdditionalTrustManager(final File additionalTrustStoreFile, final char[] trustStorePassword) throws Exception {
		final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		try (FileInputStream fis = new FileInputStream(additionalTrustStoreFile)) {
			keyStore.load(fis, trustStorePassword);
		}

		final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(keyStore);

		for (final TrustManager tm : tmf.getTrustManagers()) {
			if (tm instanceof X509TrustManager) {
				return (X509TrustManager) tm;
			}
		}

		throw new IllegalStateException("No additional X509TrustManager found");
	}

	@Override
	public void checkClientTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
		try {
			systemDefaultTrustManager.checkClientTrusted(chain, authType);
		} catch (@SuppressWarnings("unused") final CertificateException e) {
			additionalTrustManager.checkClientTrusted(chain, authType);
		}
	}

	@Override
	public void checkServerTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
		try {
			systemDefaultTrustManager.checkServerTrusted(chain, authType);
		} catch (@SuppressWarnings("unused") final CertificateException e) {
			additionalTrustManager.checkServerTrusted(chain, authType);
		}
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		// getAcceptedIssuers() is permitted to return null per the X509TrustManager contract,
		// so this must not be assumed to always be a (possibly empty) array.
		final X509Certificate[] systemDefaultIssuers = systemDefaultTrustManager.getAcceptedIssuers();
		final X509Certificate[] additionalIssuers = additionalTrustManager.getAcceptedIssuers();

		final int systemDefaultCount = systemDefaultIssuers == null ? 0 : systemDefaultIssuers.length;
		final int additionalCount = additionalIssuers == null ? 0 : additionalIssuers.length;

		final X509Certificate[] allIssuers = new X509Certificate[systemDefaultCount + additionalCount];

		if (systemDefaultCount > 0) {
			System.arraycopy(systemDefaultIssuers, 0, allIssuers, 0, systemDefaultCount);
		}
		if (additionalCount > 0) {
			System.arraycopy(additionalIssuers, 0, allIssuers, systemDefaultCount, additionalCount);
		}

		return allIssuers;
	}
}
