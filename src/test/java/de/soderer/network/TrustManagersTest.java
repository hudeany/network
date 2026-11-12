package de.soderer.network;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import de.soderer.network.trustmanager.AdditionalTruststoreTrustManager;
import de.soderer.network.trustmanager.PemFileTrustManager;
import de.soderer.network.trustmanager.SavingToPemFileTrustManager;
import de.soderer.network.trustmanager.SavingToTruststoreTrustManager;
import de.soderer.network.trustmanager.TruststoreTrustManager;

/**
 * Tests for the X509TrustManager implementations in de.soderer.network.trustmanager, using
 * locally generated self-signed certificates.
 */
@SuppressWarnings("static-method")
public class TrustManagersTest {
	private static final String AUTH_TYPE = "RSA";

	@TempDir
	File tempDir;

	private static X509Certificate[] chainOf(final X509Certificate certificate) {
		return new X509Certificate[] { certificate };
	}

	// ---------------------------------------------------------------- TruststoreTrustManager

	@Test
	public void testTruststoreTrustManagerAcceptsOnlyContainedCertificates() throws Exception {
		final File truststore = TestTlsSupport.writeTruststore(new File(tempDir, "trust.p12"), "secret".toCharArray(), TestTlsSupport.getLocalhostCertificate());
		final TruststoreTrustManager trustManager = new TruststoreTrustManager(truststore, "secret".toCharArray());

		assertDoesNotThrow(() -> trustManager.checkServerTrusted(chainOf(TestTlsSupport.getLocalhostCertificate()), AUTH_TYPE));
		assertDoesNotThrow(() -> trustManager.checkClientTrusted(chainOf(TestTlsSupport.getLocalhostCertificate()), AUTH_TYPE));
		assertThrows(CertificateException.class, () -> trustManager.checkServerTrusted(chainOf(TestTlsSupport.getOtherCertificate()), AUTH_TYPE));
		assertThrows(CertificateException.class, () -> trustManager.checkClientTrusted(chainOf(TestTlsSupport.getOtherCertificate()), AUTH_TYPE));

		final X509Certificate[] acceptedIssuers = trustManager.getAcceptedIssuers();
		assertEquals(1, acceptedIssuers.length);
		assertEquals(TestTlsSupport.getLocalhostCertificate(), acceptedIssuers[0]);
	}

	@Test
	public void testTruststoreTrustManagerWithMissingFileFails() {
		assertThrows(Exception.class, () -> new TruststoreTrustManager(new File(tempDir, "missing.p12"), null));
	}

	// ---------------------------------------------------------------- PemFileTrustManager

	@Test
	public void testPemFileTrustManagerAcceptsOnlyThePemCertificate() throws Exception {
		final PemFileTrustManager trustManager = new PemFileTrustManager(TestTlsSupport.getLocalhostPemFile());

		assertDoesNotThrow(() -> trustManager.checkServerTrusted(chainOf(TestTlsSupport.getLocalhostCertificate()), AUTH_TYPE));
		assertDoesNotThrow(() -> trustManager.checkClientTrusted(chainOf(TestTlsSupport.getLocalhostCertificate()), AUTH_TYPE));
		assertThrows(CertificateException.class, () -> trustManager.checkServerTrusted(chainOf(TestTlsSupport.getOtherCertificate()), AUTH_TYPE));
		assertThrows(CertificateException.class, () -> trustManager.checkClientTrusted(chainOf(TestTlsSupport.getOtherCertificate()), AUTH_TYPE));
		assertEquals(1, trustManager.getAcceptedIssuers().length);
	}

	@Test
	public void testPemFileTrustManagerWithInvalidFileFails() throws Exception {
		final File invalidPem = new File(tempDir, "invalid.pem");
		java.nio.file.Files.writeString(invalidPem.toPath(), "this is no certificate");
		assertThrows(Exception.class, () -> new PemFileTrustManager(invalidPem));
		assertThrows(Exception.class, () -> new PemFileTrustManager(new File(tempDir, "missing.pem")));
	}

	// ---------------------------------------------------------------- AdditionalTruststoreTrustManager

	@Test
	public void testAdditionalTruststoreTrustManagerFallsBackToAdditionalTruststore() throws Exception {
		final File truststore = TestTlsSupport.writeTruststore(new File(tempDir, "additional.p12"), "secret".toCharArray(), TestTlsSupport.getLocalhostCertificate());
		final AdditionalTruststoreTrustManager trustManager = new AdditionalTruststoreTrustManager(truststore, "secret".toCharArray());

		// self-signed certificate is rejected by the system truststore, but accepted by the additional one
		assertDoesNotThrow(() -> trustManager.checkServerTrusted(chainOf(TestTlsSupport.getLocalhostCertificate()), AUTH_TYPE));
		assertDoesNotThrow(() -> trustManager.checkClientTrusted(chainOf(TestTlsSupport.getLocalhostCertificate()), AUTH_TYPE));

		// a certificate known to neither truststore is still rejected
		assertThrows(CertificateException.class, () -> trustManager.checkServerTrusted(chainOf(TestTlsSupport.getOtherCertificate()), AUTH_TYPE));
		assertThrows(CertificateException.class, () -> trustManager.checkClientTrusted(chainOf(TestTlsSupport.getOtherCertificate()), AUTH_TYPE));

		// accepted issuers combine the system default issuers and the additional certificate
		final X509Certificate[] acceptedIssuers = trustManager.getAcceptedIssuers();
		assertTrue(acceptedIssuers.length >= 1);
		boolean containsAdditionalCertificate = false;
		for (final X509Certificate issuer : acceptedIssuers) {
			assertNotNull(issuer);
			if (issuer.equals(TestTlsSupport.getLocalhostCertificate())) {
				containsAdditionalCertificate = true;
			}
		}
		assertTrue(containsAdditionalCertificate);
	}

	@Test
	public void testAdditionalTruststoreTrustManagerWithEmptyAdditionalTruststore() throws Exception {
		final File truststore = TestTlsSupport.writeTruststore(new File(tempDir, "empty.p12"), "secret".toCharArray());
		// TrustManagerFactory refuses an empty truststore with an exception, or creates a manager without issuers
		try {
			final AdditionalTruststoreTrustManager trustManager = new AdditionalTruststoreTrustManager(truststore, "secret".toCharArray());
			assertNotNull(trustManager.getAcceptedIssuers());
		} catch (@SuppressWarnings("unused") final Exception e) {
			// acceptable, depends on the JDK's trust manager implementation
		}
	}

	@Test
	public void testAdditionalTruststoreTrustManagerWithMissingFileFails() {
		assertThrows(Exception.class, () -> new AdditionalTruststoreTrustManager(new File(tempDir, "missing.p12"), null));
	}

	// ---------------------------------------------------------------- SavingToTruststoreTrustManager

	@Test
	public void testSavingToTruststoreTrustManagerRecordsFirstCertificateAndPinsIt() throws Exception {
		final File truststore = new File(tempDir, "tofu.p12");
		final char[] password = "secret".toCharArray();

		final SavingToTruststoreTrustManager trustManager = new SavingToTruststoreTrustManager(truststore, password);
		assertNull(trustManager.getServerCertificate());
		assertEquals(0, trustManager.getAcceptedIssuers().length);
		assertDoesNotThrow(() -> trustManager.checkClientTrusted(chainOf(TestTlsSupport.getOtherCertificate()), AUTH_TYPE));

		// null and empty chains are ignored and do not record anything
		trustManager.checkServerTrusted(null, AUTH_TYPE);
		trustManager.checkServerTrusted(new X509Certificate[0], AUTH_TYPE);
		assertFalse(truststore.exists());

		// first use: accepted and recorded
		trustManager.checkServerTrusted(chainOf(TestTlsSupport.getLocalhostCertificate()), AUTH_TYPE);
		assertTrue(truststore.exists());
		assertSame(TestTlsSupport.getLocalhostCertificate(), trustManager.getServerCertificate());

		// same certificate again on the same instance: accepted
		trustManager.checkServerTrusted(chainOf(TestTlsSupport.getLocalhostCertificate()), AUTH_TYPE);

		// different certificate on the same instance: rejected
		assertThrows(CertificateException.class, () -> trustManager.checkServerTrusted(chainOf(TestTlsSupport.getOtherCertificate()), AUTH_TYPE));

		// the recorded truststore file contains exactly the recorded certificate
		final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		try (FileInputStream inputStream = new FileInputStream(truststore)) {
			keyStore.load(inputStream, password);
		}
		assertEquals(1, keyStore.size());
		assertEquals(TestTlsSupport.getLocalhostCertificate(), keyStore.getCertificate(keyStore.aliases().nextElement()));

		// a new instance on the existing file keeps the pinning
		final SavingToTruststoreTrustManager secondTrustManager = new SavingToTruststoreTrustManager(truststore, password);
		secondTrustManager.checkServerTrusted(chainOf(TestTlsSupport.getLocalhostCertificate()), AUTH_TYPE);
		assertSame(TestTlsSupport.getLocalhostCertificate(), secondTrustManager.getServerCertificate());
		assertThrows(CertificateException.class, () -> secondTrustManager.checkServerTrusted(chainOf(TestTlsSupport.getOtherCertificate()), AUTH_TYPE));
	}

	@Test
	public void testSavingToTruststoreTrustManagerRecordsWholeChainWithoutDuplicates() throws Exception {
		final File truststore = new File(tempDir, "chain.p12");
		final char[] password = "secret".toCharArray();
		final SavingToTruststoreTrustManager trustManager = new SavingToTruststoreTrustManager(truststore, password);

		// the same certificate twice in the chain must only be stored once
		trustManager.checkServerTrusted(new X509Certificate[] { TestTlsSupport.getLocalhostCertificate(), TestTlsSupport.getOtherCertificate(), TestTlsSupport.getLocalhostCertificate() }, AUTH_TYPE);

		final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		try (FileInputStream inputStream = new FileInputStream(truststore)) {
			keyStore.load(inputStream, password);
		}
		assertEquals(2, keyStore.size());
	}

	@Test
	public void testSavingToTruststoreTrustManagerWithUnwritableFileThrowsRuntimeException() throws Exception {
		// A directory cannot be opened as FileOutputStream, so recording fails
		final File directoryAsTruststore = new File(tempDir, "isADirectory");
		final SavingToTruststoreTrustManager trustManager = new SavingToTruststoreTrustManager(directoryAsTruststore, null);
		assertTrue(directoryAsTruststore.mkdir());
		assertThrows(RuntimeException.class, () -> trustManager.checkServerTrusted(chainOf(TestTlsSupport.getLocalhostCertificate()), AUTH_TYPE));
	}

	@Test
	public void testSavingToTruststoreTrustManagerWithWrongPasswordFails() throws Exception {
		final File truststore = TestTlsSupport.writeTruststore(new File(tempDir, "pw.p12"), "secret".toCharArray(), TestTlsSupport.getLocalhostCertificate());
		assertThrows(Exception.class, () -> new SavingToTruststoreTrustManager(truststore, "wrong".toCharArray()));
	}

	// ---------------------------------------------------------------- SavingToPemFileTrustManager

	@Test
	public void testSavingToPemFileTrustManagerBasics() throws Exception {
		final File pemFile = new File(tempDir, "tofu.pem");
		final SavingToPemFileTrustManager trustManager = new SavingToPemFileTrustManager(pemFile);
		assertNull(trustManager.getServerCertificate());
		assertEquals(0, trustManager.getAcceptedIssuers().length);
		assertDoesNotThrow(() -> trustManager.checkClientTrusted(chainOf(TestTlsSupport.getOtherCertificate()), AUTH_TYPE));

		trustManager.checkServerTrusted(null, AUTH_TYPE);
		trustManager.checkServerTrusted(new X509Certificate[0], AUTH_TYPE);
		assertFalse(pemFile.exists());

		trustManager.checkServerTrusted(chainOf(TestTlsSupport.getLocalhostCertificate()), AUTH_TYPE);
		assertSame(TestTlsSupport.getLocalhostCertificate(), trustManager.getServerCertificate());
		assertEquals(TestTlsSupport.getLocalhostCertificate(), TestTlsSupport.readPemCertificate(pemFile));

		// Accepted again with the same certificate
		trustManager.checkServerTrusted(chainOf(TestTlsSupport.getLocalhostCertificate()), AUTH_TYPE);

		// A null pem file is treated as "nothing recorded yet"
		final SavingToPemFileTrustManager nullFileTrustManager = new SavingToPemFileTrustManager(null);
		assertNull(nullFileTrustManager.getServerCertificate());
		assertThrows(RuntimeException.class, () -> nullFileTrustManager.checkServerTrusted(chainOf(TestTlsSupport.getLocalhostCertificate()), AUTH_TYPE));
	}

	@Test
	public void testSavingToPemFileTrustManagerWithEmptyExistingFile() throws Exception {
		final File pemFile = new File(tempDir, "empty.pem");
		assertTrue(pemFile.createNewFile());
		final SavingToPemFileTrustManager trustManager = new SavingToPemFileTrustManager(pemFile);
		trustManager.checkServerTrusted(chainOf(TestTlsSupport.getOtherCertificate()), AUTH_TYPE);
		assertEquals(TestTlsSupport.getOtherCertificate(), TestTlsSupport.readPemCertificate(pemFile));
	}
}
