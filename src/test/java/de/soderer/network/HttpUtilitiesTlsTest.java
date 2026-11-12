package de.soderer.network;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.Proxy;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpsServer;

import de.soderer.network.trustmanager.PemFileTrustManager;
import de.soderer.network.trustmanager.TrustManagerUtilities;

/**
 * HTTPS tests of {@link HttpUtilities} against a local server with a self-signed certificate.
 */
@SuppressWarnings("static-method")
public class HttpUtilitiesTlsTest {
	private HttpsServer server;

	@AfterEach
	public void stopServer() {
		if (server != null) {
			server.stop(0);
		}
	}

	private String startLocalhostServer() throws Exception {
		server = TestTlsSupport.startHttpsServer(exchange -> TestTlsSupport.respond(exchange, 200, "secure"));
		return "https://localhost:" + server.getAddress().getPort() + "/";
	}

	@Test
	public void testHttpsWithCustomTrustManager() throws Exception {
		final String url = startLocalhostServer();
		final HttpResponse response = HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, url), Proxy.NO_PROXY,
				new PemFileTrustManager(TestTlsSupport.getLocalhostPemFile()), false);
		assertEquals(200, response.getHttpCode());
		assertEquals("secure", response.getContent());
	}

	@Test
	public void testHttpsWithTrustedKeyStore() throws Exception {
		final String url = startLocalhostServer();
		final KeyStore trustedKeyStore = TestTlsSupport.createTrustKeyStore(TestTlsSupport.getLocalhostCertificate());
		final HttpResponse response = HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, url), null, trustedKeyStore);
		assertEquals("secure", response.getContent());
	}

	@Test
	public void testHttpsWithEmptyKeyStoreIsRejected() throws Exception {
		final KeyStore emptyKeyStore = TestTlsSupport.createTrustKeyStore();
		final Exception exception = assertThrows(Exception.class,
				() -> HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, "https://localhost/"), null, emptyKeyStore));
		assertTrue(exception.getMessage().contains("No trusted certificate"));
	}

	@Test
	public void testHttpsWithSystemTruststoreRejectsSelfSignedCertificate() throws Exception {
		final String url = startLocalhostServer();
		final Exception exception = assertThrows(Exception.class, () -> HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, url)));
		assertTrue(exception.getMessage().contains("Cannot validate TLS server certificate"), exception.getMessage());
		assertTrue(exception.getMessage().contains("(Certificate chain error)"), exception.getMessage());
	}

	@Test
	public void testHttpsTrustAllWithAndWithoutHostnameVerification() throws Exception {
		// The certificate of this server is issued for "other.test", not for "localhost"
		server = TestTlsSupport.startHttpsServer(TestTlsSupport.getOtherKeystoreFile(), exchange -> TestTlsSupport.respond(exchange, 200, "other"));
		final String url = "https://localhost:" + server.getAddress().getPort() + "/";

		final Exception exception = assertThrows(Exception.class, () -> HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, url), null,
				new PemFileTrustManager(TestTlsSupport.getOtherPemFile()), false));
		assertNotNull(exception.getMessage());

		final HttpResponse response = HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, url), null,
				TrustManagerUtilities.createTrustAllTrustManager(), true);
		assertEquals("other", response.getContent());
	}

	@Test
	public void testPingHttpsUrlWithoutCertificateCheck() throws Exception {
		final String url = startLocalhostServer();
		HttpUtilities.pingUrlWithoutSslCheckNoWaitForAnswer(url, null);
	}

	@Test
	public void testGetServerTlsCertificate() throws Exception {
		startLocalhostServer();
		final X509Certificate certificateWithAlternativeNames = HttpUtilities.getServerTlsCertificate("localhost", server.getAddress().getPort(), null);
		assertEquals(TestTlsSupport.getLocalhostCertificate(), certificateWithAlternativeNames);
		server.stop(0);

		// A certificate without subject alternative names is returned as fallback
		server = TestTlsSupport.startHttpsServer(TestTlsSupport.getOtherKeystoreFile(), exchange -> TestTlsSupport.respond(exchange, 200, "other"));
		final X509Certificate certificateWithoutAlternativeNames = HttpUtilities.getServerTlsCertificate("localhost", server.getAddress().getPort(), Proxy.NO_PROXY);
		assertEquals(TestTlsSupport.getOtherCertificate(), certificateWithoutAlternativeNames);
	}
}
