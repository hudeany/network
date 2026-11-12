package de.soderer.network;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.net.Proxy;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.sun.net.httpserver.HttpsServer;

import de.soderer.network.trustmanager.TrustManagerUtilities;

/**
 * Tests for {@link TrustManagerUtilities}.
 */
@SuppressWarnings("static-method")
public class TrustManagerUtilitiesTest {
	@TempDir
	File tempDir;

	@Test
	public void testDefaultTrustManagers() throws Exception {
		final TrustManager[] trustManagers = TrustManagerUtilities.getDefaultTrustManagers();
		assertNotNull(trustManagers);
		assertTrue(trustManagers.length > 0);

		final X509TrustManager defaultTrustManager = TrustManagerUtilities.getDefaultTrustManager();
		assertNotNull(defaultTrustManager);
		// a self-signed certificate is not trusted by the system truststore
		assertThrows(CertificateException.class, () -> defaultTrustManager.checkServerTrusted(new X509Certificate[] { TestTlsSupport.getLocalhostCertificate() }, "RSA"));
	}

	@Test
	public void testTrustAllTrustManagerAcceptsEverything() throws Exception {
		final X509TrustManager trustManager = TrustManagerUtilities.createTrustAllTrustManager();
		final X509Certificate[] chain = new X509Certificate[] { TestTlsSupport.getOtherCertificate() };
		assertDoesNotThrow(() -> trustManager.checkServerTrusted(chain, "RSA"));
		assertDoesNotThrow(() -> trustManager.checkClientTrusted(chain, "RSA"));
		assertDoesNotThrow(() -> trustManager.checkServerTrusted(null, null));
		assertNotNull(trustManager.getAcceptedIssuers());
		assertEquals(0, trustManager.getAcceptedIssuers().length);
	}

	@Test
	public void testReadKeyStoreFromStreamAndFile() throws Exception {
		final File truststore = TestTlsSupport.writeTruststore(new File(tempDir, "trust.p12"), "secret".toCharArray(), TestTlsSupport.getLocalhostCertificate());
		final byte[] truststoreBytes = Files.readAllBytes(truststore.toPath());

		assertEquals(1, TrustManagerUtilities.readKeyStore(new ByteArrayInputStream(truststoreBytes), "secret".toCharArray()).size());
		assertEquals(1, TrustManagerUtilities.readKeyStore(truststore, "secret".toCharArray()).size());

		// Without password the protected store appears empty, so the retry with an empty password is
		// made, which fails for a store protected by a real password
		assertThrows(Exception.class, () -> TrustManagerUtilities.readKeyStore(truststore));
		assertThrows(Exception.class, () -> TrustManagerUtilities.readKeyStore(new ByteArrayInputStream(truststoreBytes)));

		assertThrows(Exception.class, () -> TrustManagerUtilities.readKeyStore(new ByteArrayInputStream(truststoreBytes), "wrong".toCharArray()));
		assertThrows(Exception.class, () -> TrustManagerUtilities.readKeyStore(new File(tempDir, "missing.p12"), null));
	}

	@Test
	public void testReadKeyStoreWithEmptyPasswordIsRetried() throws Exception {
		// A store saved with an empty password: reading without password must retry with ""
		final File truststore = TestTlsSupport.writeTruststore(new File(tempDir, "emptypw.p12"), new char[0], TestTlsSupport.getLocalhostCertificate());
		final byte[] truststoreBytes = Files.readAllBytes(truststore.toPath());

		assertEquals(1, TrustManagerUtilities.readKeyStore(truststore).size());
		assertEquals(1, TrustManagerUtilities.readKeyStore(new ByteArrayInputStream(truststoreBytes)).size());

		// An empty store without password stays empty after the retry
		final File emptyTruststore = TestTlsSupport.writeTruststore(new File(tempDir, "empty.p12"), new char[0]);
		assertEquals(0, TrustManagerUtilities.readKeyStore(emptyTruststore).size());
		assertEquals(0, TrustManagerUtilities.readKeyStore(new ByteArrayInputStream(Files.readAllBytes(emptyTruststore.toPath()))).size());
	}

	@Test
	public void testCreateTrustManagerForKeyStoreVariants() throws Exception {
		final File truststore = TestTlsSupport.writeTruststore(new File(tempDir, "trust.p12"), "secret".toCharArray(), TestTlsSupport.getLocalhostCertificate());
		final File truststoreEmptyPassword = TestTlsSupport.writeTruststore(new File(tempDir, "trust-nopw.p12"), new char[0], TestTlsSupport.getLocalhostCertificate());
		final X509Certificate[] trustedChain = new X509Certificate[] { TestTlsSupport.getLocalhostCertificate() };
		final X509Certificate[] untrustedChain = new X509Certificate[] { TestTlsSupport.getOtherCertificate() };

		final TrustManager[] trustManagers;
		try (FileInputStream withPasswordStream = new FileInputStream(truststore);
				FileInputStream withoutPasswordStream = new FileInputStream(truststoreEmptyPassword)) {
			trustManagers = new TrustManager[] {
					TrustManagerUtilities.createTrustManagerForKeyStore(truststore, "secret".toCharArray()),
					TrustManagerUtilities.createTrustManagerForKeyStore(truststoreEmptyPassword),
					TrustManagerUtilities.createTrustManagerForKeyStore(withPasswordStream, "secret".toCharArray()),
					TrustManagerUtilities.createTrustManagerForKeyStore(withoutPasswordStream),
					TrustManagerUtilities.createTrustManagerForKeyStore(TestTlsSupport.createTrustKeyStore(TestTlsSupport.getLocalhostCertificate())) };
		}

		for (final TrustManager trustManager : trustManagers) {
			final X509TrustManager x509TrustManager = (X509TrustManager) trustManager;
			assertDoesNotThrow(() -> x509TrustManager.checkServerTrusted(trustedChain, "RSA"));
			assertThrows(CertificateException.class, () -> x509TrustManager.checkServerTrusted(untrustedChain, "RSA"));
		}
	}

	@Test
	public void testCreateTrustStoreFileFailsForExistingFile() throws Exception {
		final File existingFile = new File(tempDir, "exists.p12");
		assertTrue(existingFile.createNewFile());
		final Exception exception = assertThrows(Exception.class, () -> TrustManagerUtilities.createTrustStoreFile("localhost:443", 443, existingFile, null, null));
		assertTrue(exception.getMessage().contains("already exists"));
	}

	@Test
	public void testCreateTrustStoreFileRejectsInvalidHostSpecifications() {
		final File target = new File(tempDir, "never.p12");

		final Exception missingBracket = assertThrows(Exception.class, () -> TrustManagerUtilities.createTrustStoreFile("[::1:8443", 443, target, null, null));
		assertTrue(missingBracket.getMessage().contains("missing closing ']'"));

		final Exception invalidBracketedPort = assertThrows(Exception.class, () -> TrustManagerUtilities.createTrustStoreFile("[::1]:abc", 443, target, null, null));
		assertTrue(invalidBracketedPort.getMessage().contains("Invalid port"));

		final Exception invalidPort = assertThrows(Exception.class, () -> TrustManagerUtilities.createTrustStoreFile("localhost:abc", 443, target, null, null));
		assertTrue(invalidPort.getMessage().contains("Invalid port"));
	}

	@Test
	public void testCreateTrustStoreFileFromLocalHttpsServer() throws Exception {
		final HttpsServer server = TestTlsSupport.startHttpsServer(exchange -> TestTlsSupport.respond(exchange, 200, "OK"));
		try {
			final int port = server.getAddress().getPort();

			// "host:port" notation with password
			final File truststoreWithPassword = new File(tempDir, "server1.p12");
			TrustManagerUtilities.createTrustStoreFile("localhost:" + port, 1, truststoreWithPassword, "secret".toCharArray(), Proxy.NO_PROXY);
			final KeyStore keyStoreWithPassword = TrustManagerUtilities.readKeyStore(truststoreWithPassword, "secret".toCharArray());
			assertEquals(1, keyStoreWithPassword.size());
			assertEquals(TestTlsSupport.getLocalhostCertificate(), keyStoreWithPassword.getCertificate("localhost"));

			// bracketed notation with port, without password
			final File truststoreBracketed = new File(tempDir, "server2.p12");
			TrustManagerUtilities.createTrustStoreFile("[localhost]:" + port, 1, truststoreBracketed, null, null);
			assertEquals(1, TrustManagerUtilities.readKeyStore(truststoreBracketed).size());

			// bracketed notation without port uses the default port
			final File truststoreBracketedDefaultPort = new File(tempDir, "server3.p12");
			TrustManagerUtilities.createTrustStoreFile("[localhost]", port, truststoreBracketedDefaultPort, null, null);
			assertEquals(1, TrustManagerUtilities.readKeyStore(truststoreBracketedDefaultPort).size());

			// bare host uses the default port
			final File truststoreBareHost = new File(tempDir, "server4.p12");
			TrustManagerUtilities.createTrustStoreFile("localhost", port, truststoreBareHost, null, null);
			assertEquals(1, TrustManagerUtilities.readKeyStore(truststoreBareHost).size());
		} finally {
			server.stop(0);
		}
	}
}
