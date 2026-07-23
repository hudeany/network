package de.soderer.network.trustmanager;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

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
 *
 * <p><b>Trust-on-first-use semantics:</b> if {@code pemFile} does not yet exist (or is empty), the
 * first server certificate seen is accepted unconditionally and recorded to the file. If the file
 * already contains a previously recorded certificate, any further connection is only accepted if
 * the presented leaf certificate's fingerprint matches one that was already recorded; otherwise
 * a {@link CertificateException} is thrown instead of silently accepting (and overwriting) a
 * different certificate, which would otherwise defeat the purpose of pinning.</p>
 */
public class SavingToPemFileTrustManager implements X509TrustManager {
	private final File pemFile;
	private final List<String> previouslyRecordedFingerprints;
	private X509Certificate serverCertificate;

	public SavingToPemFileTrustManager(final File pemFile) throws Exception {
		this.pemFile = pemFile;
		previouslyRecordedFingerprints = readFingerprints(pemFile);
	}

	private static List<String> readFingerprints(final File pemFile) throws Exception {
		final List<String> fingerprints = new ArrayList<>();
		if (pemFile != null && pemFile.exists() && pemFile.length() > 0) {
			final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			try (FileInputStream fileInputStream = new FileInputStream(pemFile)) {
				for (final java.security.cert.Certificate certificate : certificateFactory.generateCertificates(fileInputStream)) {
					fingerprints.add(fingerprint(certificate.getEncoded()));
				}
			}
		}
		return fingerprints;
	}

	private static String fingerprint(final byte[] encodedCertificate) throws Exception {
		final MessageDigest digest = MessageDigest.getInstance("SHA-256");
		return Base64.getEncoder().encodeToString(digest.digest(encodedCertificate));
	}

	public X509Certificate getServerCertificate() {
		return serverCertificate;
	}

	@Override
	public void checkClientTrusted(final X509Certificate[] chain, final String authType) {
		// do nothing
	}

	@Override
	public void checkServerTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
		try {
			if (chain != null && chain.length > 0) {
				if (!previouslyRecordedFingerprints.isEmpty()) {
					// A certificate was already recorded earlier: only accept if the presented leaf
					// certificate matches one we have already seen, instead of blindly trusting and
					// overwriting whatever is presented now.
					final String presentedFingerprint = fingerprint(chain[0].getEncoded());
					if (!previouslyRecordedFingerprints.contains(presentedFingerprint)) {
						throw new CertificateException("Presented server certificate does not match the certificate previously recorded in '"
								+ pemFile.getAbsolutePath() + "' - possible certificate change or man-in-the-middle attempt");
					}
					serverCertificate = chain[0];
					return;
				}

				serverCertificate = chain[0];
				try (FileWriter writer = new FileWriter(pemFile)) {
					for (final X509Certificate cert : chain) {
						writer.write("-----BEGIN CERTIFICATE-----\n");
						writer.write(Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded()));
						writer.write("\n-----END CERTIFICATE-----\n");
						previouslyRecordedFingerprints.add(fingerprint(cert.getEncoded()));
					}
				}
			}
		} catch (final CertificateException e) {
			throw e;
		} catch (final Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return new X509Certificate[0];
	}
}
