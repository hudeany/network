package de.soderer.utilities;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.Test;

import de.soderer.network.trustmanager.SavingToPemFileTrustManager;

/**
 * Regression test for the certificate-pinning bypass: previously, after the first
 * "trust on first use" write, the in-memory fingerprint list was never updated, so every
 * subsequent connection on the same trust manager instance was (incorrectly) treated as a
 * fresh first-use and blindly accepted whatever certificate was presented, regardless of
 * whether it matched the previously pinned one.
 */
@SuppressWarnings("static-method")
public class SavingToPemFileTrustManagerTest {
	private static X509Certificate generateSelfSignedCertificate(final File workDir, final String alias) throws Exception {
		final File keystoreFile = new File(workDir, alias + ".jks");
		final File pemFile = new File(workDir, alias + ".pem");
		final String keytoolPath = System.getProperty("java.home") + File.separator + "bin" + File.separator + "keytool";

		runProcess(keytoolPath, "-genkeypair",
				"-alias", alias,
				"-keyalg", "RSA",
				"-keysize", "2048",
				"-validity", "1",
				"-dname", "CN=" + alias + ".test",
				"-keystore", keystoreFile.getAbsolutePath(),
				"-storepass", "changeit",
				"-keypass", "changeit");

		runProcess(keytoolPath, "-exportcert",
				"-alias", alias,
				"-keystore", keystoreFile.getAbsolutePath(),
				"-storepass", "changeit",
				"-rfc",
				"-file", pemFile.getAbsolutePath());

		try (FileInputStream certificateInputStream = new FileInputStream(pemFile)) {
			return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(certificateInputStream);
		}
	}

	private static void runProcess(final String... command) throws Exception {
		final Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
		process.getInputStream().readAllBytes();
		final int exitCode = process.waitFor();
		if (exitCode != 0) {
			throw new IllegalStateException("Command failed with exit code " + exitCode + ": " + String.join(" ", command));
		}
	}

	@Test
	public void testPinningRejectsADifferentCertificateOnASecondConnectionOfTheSameInstance() throws Exception {
		final File workDir = Files.createTempDirectory("pem-trustmanager-test").toFile();
		try {
			final X509Certificate cert1 = generateSelfSignedCertificate(workDir, "cert1");
			final X509Certificate cert2 = generateSelfSignedCertificate(workDir, "cert2");

			final File pinFile = new File(workDir, "pinned.pem");
			final SavingToPemFileTrustManager trustManager = new SavingToPemFileTrustManager(pinFile);

			// First connection: trust-on-first-use, records cert1
			trustManager.checkServerTrusted(new X509Certificate[] { cert1 }, "RSA");
			assertNotNull(trustManager.getServerCertificate());

			// Second connection, SAME certificate: must still be accepted
			trustManager.checkServerTrusted(new X509Certificate[] { cert1 }, "RSA");

			// Third connection, DIFFERENT certificate on the SAME instance: must now be rejected,
			// since the in-memory fingerprint list is correctly updated after the first write
			try {
				trustManager.checkServerTrusted(new X509Certificate[] { cert2 }, "RSA");
				fail("Expected a CertificateException for a certificate that differs from the pinned one");
			} catch (@SuppressWarnings("unused") final CertificateException e) {
				// expected
			}
		} finally {
			deleteRecursively(workDir);
		}
	}

	private static void deleteRecursively(final File file) {
		final File[] children = file.listFiles();
		if (children != null) {
			for (final File child : children) {
				deleteRecursively(child);
			}
		}
		file.delete();
	}
}
