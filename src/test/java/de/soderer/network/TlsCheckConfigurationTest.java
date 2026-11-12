package de.soderer.network;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import de.soderer.network.TlsCheckConfiguration.TlsCheckConfigurationType;
import de.soderer.network.trustmanager.AdditionalTruststoreTrustManager;
import de.soderer.network.trustmanager.PemFileTrustManager;
import de.soderer.network.trustmanager.SavingToPemFileTrustManager;
import de.soderer.network.trustmanager.SavingToTruststoreTrustManager;
import de.soderer.network.trustmanager.TruststoreTrustManager;

/**
 * Tests for {@link TlsCheckConfiguration} and its type enum.
 */
@SuppressWarnings("static-method")
public class TlsCheckConfigurationTest {
	@TempDir
	File tempDir;

	@Test
	public void testTypeFlags() {
		assertFalse(TlsCheckConfigurationType.SystemTrustStore.isFilePathSupported());
		assertFalse(TlsCheckConfigurationType.SystemTrustStore.isPasswordSupported());
		assertTrue(TlsCheckConfigurationType.TrustStoreFile.isFilePathSupported());
		assertTrue(TlsCheckConfigurationType.TrustStoreFile.isPasswordSupported());
		assertTrue(TlsCheckConfigurationType.AdditionalTrustStoreFile.isFilePathSupported());
		assertTrue(TlsCheckConfigurationType.AdditionalTrustStoreFile.isPasswordSupported());
		assertTrue(TlsCheckConfigurationType.RecordingToTrustStoreFile.isFilePathSupported());
		assertTrue(TlsCheckConfigurationType.RecordingToTrustStoreFile.isPasswordSupported());
		assertTrue(TlsCheckConfigurationType.SingleCertificate.isFilePathSupported());
		assertFalse(TlsCheckConfigurationType.SingleCertificate.isPasswordSupported());
		assertTrue(TlsCheckConfigurationType.RecordingSingleCertificate.isFilePathSupported());
		assertFalse(TlsCheckConfigurationType.RecordingSingleCertificate.isPasswordSupported());
		assertFalse(TlsCheckConfigurationType.NoCheck.isFilePathSupported());
		assertFalse(TlsCheckConfigurationType.NoCheck.isPasswordSupported());
	}

	@Test
	public void testTypeByName() throws Exception {
		for (final TlsCheckConfigurationType type : TlsCheckConfigurationType.values()) {
			assertSame(type, TlsCheckConfigurationType.getTlsCheckConfigurationByName(type.name()));
			assertSame(type, TlsCheckConfigurationType.getTlsCheckConfigurationByName(type.name().toUpperCase()));
			assertSame(type, TlsCheckConfigurationType.getTlsCheckConfigurationByName(type.name().toLowerCase()));
		}
		final Exception exception = assertThrows(Exception.class, () -> TlsCheckConfigurationType.getTlsCheckConfigurationByName("Unknown"));
		assertTrue(exception.getMessage().contains("Unknown"));
		assertThrows(Exception.class, () -> TlsCheckConfigurationType.getTlsCheckConfigurationByName(null));
		assertSame(TlsCheckConfigurationType.NoCheck, TlsCheckConfigurationType.valueOf("NoCheck"));
	}

	@Test
	public void testConstructorValidation() {
		final File file = new File(tempDir, "any.p12");

		assertThrows(IllegalArgumentException.class, () -> new TlsCheckConfiguration(null, true));
		assertThrows(IllegalArgumentException.class, () -> new TlsCheckConfiguration(TlsCheckConfigurationType.TrustStoreFile, true));
		assertThrows(IllegalArgumentException.class, () -> new TlsCheckConfiguration(TlsCheckConfigurationType.SystemTrustStore, file, true));
		assertThrows(IllegalArgumentException.class, () -> new TlsCheckConfiguration(TlsCheckConfigurationType.SingleCertificate, file, "pw".toCharArray(), true));

		// An empty password is accepted even for types without password support
		final TlsCheckConfiguration emptyPassword = new TlsCheckConfiguration(TlsCheckConfigurationType.SingleCertificate, file, new char[0], false);
		assertEquals(0, emptyPassword.getTrustorePassword().length);
	}

	@Test
	public void testGetters() {
		final File file = new File(tempDir, "trust.p12");
		final char[] password = "pw".toCharArray();
		final TlsCheckConfiguration configuration = new TlsCheckConfiguration(TlsCheckConfigurationType.TrustStoreFile, file, password, true);
		assertSame(TlsCheckConfigurationType.TrustStoreFile, configuration.getType());
		assertSame(file, configuration.getTrustoreOrPemFile());
		assertArrayEquals(password, configuration.getTrustorePassword());
		assertTrue(configuration.getCheckCn());

		final TlsCheckConfiguration noCheck = new TlsCheckConfiguration(TlsCheckConfigurationType.NoCheck, false);
		assertNull(noCheck.getTrustoreOrPemFile());
		assertNull(noCheck.getTrustorePassword());
		assertFalse(noCheck.getCheckCn());
	}

	@Test
	public void testTrustManagerForEachType() throws Exception {
		final char[] password = "secret".toCharArray();
		final File truststore = TestTlsSupport.writeTruststore(new File(tempDir, "trust.p12"), password, TestTlsSupport.getLocalhostCertificate());

		final TrustManager system = new TlsCheckConfiguration(TlsCheckConfigurationType.SystemTrustStore, true).getTrustManager();
		assertInstanceOf(X509TrustManager.class, system);

		final TrustManager noCheck = new TlsCheckConfiguration(TlsCheckConfigurationType.NoCheck, false).getTrustManager();
		assertInstanceOf(X509TrustManager.class, noCheck);
		((X509TrustManager) noCheck).checkServerTrusted(new X509Certificate[] { TestTlsSupport.getOtherCertificate() }, "RSA");

		assertInstanceOf(TruststoreTrustManager.class,
				new TlsCheckConfiguration(TlsCheckConfigurationType.TrustStoreFile, truststore, password, true).getTrustManager());
		assertInstanceOf(AdditionalTruststoreTrustManager.class,
				new TlsCheckConfiguration(TlsCheckConfigurationType.AdditionalTrustStoreFile, truststore, password, true).getTrustManager());
		assertInstanceOf(SavingToTruststoreTrustManager.class,
				new TlsCheckConfiguration(TlsCheckConfigurationType.RecordingToTrustStoreFile, new File(tempDir, "record.p12"), password, true).getTrustManager());
		assertInstanceOf(PemFileTrustManager.class,
				new TlsCheckConfiguration(TlsCheckConfigurationType.SingleCertificate, TestTlsSupport.getLocalhostPemFile(), true).getTrustManager());
		assertInstanceOf(SavingToPemFileTrustManager.class,
				new TlsCheckConfiguration(TlsCheckConfigurationType.RecordingSingleCertificate, new File(tempDir, "record.pem"), true).getTrustManager());

		// Reading a missing truststore fails when the trust manager is created
		assertThrows(Exception.class, () -> new TlsCheckConfiguration(TlsCheckConfigurationType.TrustStoreFile, new File(tempDir, "missing.p12"), true).getTrustManager());
	}
}
