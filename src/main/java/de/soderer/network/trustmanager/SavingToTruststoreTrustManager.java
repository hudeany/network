package de.soderer.network.trustmanager;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

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
 *
 * <p><b>Trust-on-first-use semantics:</b> if the truststore is empty, any presented certificate
 * chain is accepted and its certificates are recorded, keyed by a SHA-256 fingerprint of the
 * certificate's encoded bytes (not the Subject DN, which two different certificates can share).
 * Once at least one certificate has been recorded, further connections are only accepted if the
 * presented leaf certificate's fingerprint matches an already-recorded one; otherwise a
 * {@link CertificateException} is thrown instead of silently accepting a different certificate.</p>
 */
public class SavingToTruststoreTrustManager implements X509TrustManager {
	private X509Certificate serverCertificate;

	private final File trustStoreFile;
	private final char[] trustStorePassword;

	private final KeyStore keyStore;
	private final Set<String> previouslyRecordedFingerprints = new HashSet<>();

	public SavingToTruststoreTrustManager(final File trustStoreFile, final char[] trustStorePassword) throws Exception {
		this.trustStoreFile = trustStoreFile;
		this.trustStorePassword = trustStorePassword;

		keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		if (trustStoreFile.exists()) {
			try (FileInputStream fis = new FileInputStream(trustStoreFile)) {
				keyStore.load(fis, trustStorePassword);
			}
			final Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				final String alias = aliases.nextElement();
				final java.security.cert.Certificate certificate = keyStore.getCertificate(alias);
				if (certificate != null) {
					previouslyRecordedFingerprints.add(fingerprint(certificate.getEncoded()));
				}
			}
		} else {
			keyStore.load(null, null);
		}
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
	// synchronized so the "no fingerprints recorded yet -> accept and write" TOFU sequence is atomic;
	// without this, two threads sharing this instance could both see an empty set at the same time
	// and both independently accept (and persist) different, unverified certificates.
	public synchronized void checkServerTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
		try {
			if (chain != null && chain.length > 0) {
				if (!previouslyRecordedFingerprints.isEmpty()) {
					// Certificates were already recorded earlier: only accept if the presented leaf
					// certificate matches one we have already seen. Comparing by fingerprint (rather
					// than by Subject DN, which two different certificates can share) avoids silently
					// accepting an unrelated certificate that merely reuses a known subject name.
					final String presentedFingerprint = fingerprint(chain[0].getEncoded());
					if (!previouslyRecordedFingerprints.contains(presentedFingerprint)) {
						throw new CertificateException("Presented server certificate does not match any certificate previously recorded in '"
								+ trustStoreFile.getAbsolutePath() + "' - possible certificate change or man-in-the-middle attempt");
					}
					serverCertificate = chain[0];
					return;
				}

				serverCertificate = chain[0];

				boolean newCertificateAdded = false;
				for (final X509Certificate cert : chain) {
					// Keyed by fingerprint instead of Subject DN, so two different certificates that
					// happen to share a subject name are stored as distinct entries rather than one
					// silently shadowing the other.
					final String certFingerprint = fingerprint(cert.getEncoded());
					if (!previouslyRecordedFingerprints.contains(certFingerprint)) {
						keyStore.setCertificateEntry(certFingerprint, cert);
						previouslyRecordedFingerprints.add(certFingerprint);
						newCertificateAdded = true;
					}
				}

				if (newCertificateAdded) {
					try (FileOutputStream fos = new FileOutputStream(trustStoreFile)) {
						keyStore.store(fos, trustStorePassword);
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
