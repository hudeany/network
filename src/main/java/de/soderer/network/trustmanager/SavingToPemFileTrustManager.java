package de.soderer.network.trustmanager;

import java.io.File;
import java.io.FileWriter;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.net.ssl.X509TrustManager;

/**
 * Usage example:
 * <pre>
 * TrustManager[] trustManagers = new TrustManager[] { new SavingToPemFileTrustManager(new File("server-cert.pem")) };
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
public class SavingToPemFileTrustManager implements X509TrustManager {
	private final File pemFile;
	private X509Certificate serverCertificate;

	public SavingToPemFileTrustManager(final File pemFile) {
		this.pemFile = pemFile;
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
			if (chain != null && chain.length > 0) {
				serverCertificate = chain[0];
				try (FileWriter writer = new FileWriter(pemFile)) {
					for (final X509Certificate cert : chain) {
						writer.write("-----BEGIN CERTIFICATE-----\n");
						writer.write(Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded()));
						writer.write("\n-----END CERTIFICATE-----\n");
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
