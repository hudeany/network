package de.soderer.network.trustmanager;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

/**
 * Usage example:
 * <pre>
 * TrustManager[] trustManagers = new TrustManager[] { new SavingToTruststoreTrustManager(new File("server-cert.jks", "changeit".toCharArray())) };
 *
 * SSLContext sslContext = SSLContext.getInstance("TLS");
 * sslContext.init(null, trustManagers, new SecureRandom());
 *
 * URL url = new URL("https://example.com");
 * HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
 *
 * connection.setSSLSocketFactory(sslContext.getSocketFactory());
 * connection.connect();
 *
 * System.out.println("Response Code: " + connection.getResponseCode());
 * </pre>
 */
public class SavingToTruststoreTrustManager implements X509TrustManager {
	private X509Certificate serverCertificate;

	private final File trustStoreFile;
	private final char[] trustStorePassword;

	private final KeyStore keyStore;

	public SavingToTruststoreTrustManager(final File trustStoreFile, final char[] trustStorePassword) throws Exception {
		this.trustStoreFile = trustStoreFile;
		this.trustStorePassword = trustStorePassword;

		keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		if (trustStoreFile.exists()) {
			try (FileInputStream fis = new FileInputStream(trustStoreFile)) {
				keyStore.load(fis, trustStorePassword);
			}
		} else {
			keyStore.load(null, null);
		}
	}

	public X509Certificate getServerCertificate() {
		return serverCertificate;
	}

	@Override
	public void checkClientTrusted(final X509Certificate[] chain, final String authType) {
		// do nothing
	}

	@Override
	public void checkServerTrusted(final X509Certificate[] chain, final String authType) {
		try {
			if (chain != null) {
				if (chain.length > 0) {
					serverCertificate = chain[0];
				}

				boolean newCertificateAdded = false;
				for (int i = 0; i < chain.length; i++) {
					final String alias = chain[i].getSubjectX500Principal().getName();
					if (keyStore.getCertificate(alias) == null) {
						keyStore.setCertificateEntry(alias, chain[i]);
						newCertificateAdded = true;
					}
				}

				if (newCertificateAdded) {
					try (FileOutputStream fos = new FileOutputStream(trustStoreFile)) {
						keyStore.store(fos, trustStorePassword);
					}
				}
			}
		} catch (final Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return new X509Certificate[0];
	}
}
