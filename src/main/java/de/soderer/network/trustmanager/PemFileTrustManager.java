package de.soderer.network.trustmanager;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Usage example:
 * <pre>
 * TrustManager[] trustManagers = new TrustManager[] { new PemFileTrustManager(new File("server-cert.pem")) };
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
public class PemFileTrustManager implements X509TrustManager {
	private final X509TrustManager trustManager;

	public PemFileTrustManager(final File pemFile) throws Exception {
		final CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate cert;
		try (FileReader fr = new FileReader(pemFile)) {
			cert = (X509Certificate) cf.generateCertificate(new BufferedInputStream(new FileInputStream(pemFile)));
		}

		final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(null, null);
		keyStore.setCertificateEntry("trusted", cert);

		final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(keyStore);

		X509TrustManager tm = null;
		for (final TrustManager m : tmf.getTrustManagers()) {
			if (m instanceof X509TrustManager) {
				tm = (X509TrustManager) m;
				break;
			}
		}

		if (tm == null) {
			throw new IllegalStateException("No X509TrustManager found");
		}

		trustManager = tm;
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
