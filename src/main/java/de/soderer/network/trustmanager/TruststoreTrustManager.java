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
 * Usage example:
 *
 * <pre>
 * TrustManager[] trustManagers = new TrustManager[] { new CustomTrustStoreTrustManager("truststore.jks", "changeit".toCharArray()) };
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
public class TruststoreTrustManager implements X509TrustManager {
	private final X509TrustManager trustManager;

	public TruststoreTrustManager(final File trustStoreFile, final char[] trustStorePassword) throws Exception {
		final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		try (FileInputStream fis = new FileInputStream(trustStoreFile)) {
			keyStore.load(fis, trustStorePassword);
		}

		final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trustManagerFactory.init(keyStore);
		X509TrustManager loadedTrustManager = null;
		for (final TrustManager manager : trustManagerFactory.getTrustManagers()) {
			if (manager instanceof X509TrustManager) {
				loadedTrustManager = (X509TrustManager) manager;
				break;
			}
		}

		if (loadedTrustManager == null) {
			throw new IllegalStateException("No X509TrustManager found");
		}

		trustManager = loadedTrustManager;
	}

	@Override
	public void checkClientTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
		trustManager.checkClientTrusted(chain, authType);
	}

	@Override
	public void checkServerTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
		trustManager.checkServerTrusted(chain, authType);
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return trustManager.getAcceptedIssuers();
	}
}
