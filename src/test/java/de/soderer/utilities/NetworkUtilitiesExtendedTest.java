package de.soderer.utilities;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;

import de.soderer.network.NetworkUtilities;

/**
 * Additional tests for {@link NetworkUtilities}, using only local servers.
 */
@SuppressWarnings("static-method")
public class NetworkUtilitiesExtendedTest {
	private static int findClosedPort() throws IOException {
		try (ServerSocket serverSocket = new ServerSocket(0)) {
			return serverSocket.getLocalPort();
		}
	}

	/** Starts a fake proxy that answers each CONNECT request with the given raw bytes, then closes */
	private static Thread startFakeProxy(final ServerSocket fakeProxy, final byte[] answer) {
		final Thread thread = new Thread(() -> {
			try (Socket client = fakeProxy.accept()) {
				final InputStream inputStream = client.getInputStream();
				// read the CONNECT request up to the blank line
				int matched = 0;
				final byte[] terminator = { '\r', '\n', '\r', '\n' };
				int current;
				while (matched < 4 && (current = inputStream.read()) != -1) {
					matched = current == terminator[matched] ? matched + 1 : (current == '\r' ? 1 : 0);
				}
				final OutputStream outputStream = client.getOutputStream();
				outputStream.write(answer);
				outputStream.flush();
				// give the client time to read everything before the socket is closed
				Thread.sleep(200);
			} catch (@SuppressWarnings("unused") final Exception e) {
				// ignore, the test checks the client side
			}
		});
		thread.setDaemon(true);
		thread.start();
		return thread;
	}

	// ---------------------------------------------------------------- connections

	@Test
	public void testDirectConnection() throws Exception {
		try (ServerSocket serverSocket = new ServerSocket(0)) {
			assertTrue(NetworkUtilities.testConnection("localhost", serverSocket.getLocalPort()));
			assertTrue(NetworkUtilities.testConnection("localhost", serverSocket.getLocalPort(), -5));
			assertTrue(NetworkUtilities.testConnection("localhost", serverSocket.getLocalPort(), 1000, null));
			assertTrue(NetworkUtilities.testConnection("localhost", serverSocket.getLocalPort(), 1000, Proxy.NO_PROXY));
		}

		final int closedPort = findClosedPort();
		final Exception refused = assertThrows(Exception.class, () -> NetworkUtilities.testConnection("127.0.0.1", closedPort, 1000));
		assertTrue(refused.getMessage().startsWith("Cannot connect to host '127.0.0.1' on port " + closedPort), refused.getMessage());

		final Exception unresolved = assertThrows(Exception.class, () -> NetworkUtilities.testConnection("unknown-host-for-test.invalid", 80, 1000));
		assertTrue(unresolved.getMessage().startsWith("Cannot resolve hostname"), unresolved.getMessage());
	}

	@Test
	public void testProxyConnectWithLeftoverHeaders() throws Exception {
		try (ServerSocket fakeProxy = new ServerSocket(0)) {
			startFakeProxy(fakeProxy, "HTTP/1.1 200 OK\r\nProxy-Agent: test\r\nX-More: 1\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
			final Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", fakeProxy.getLocalPort()));
			assertTrue(NetworkUtilities.testConnection("example.invalid", 443, 2000, proxy));
		}
	}

	@Test
	public void testProxyConnectWithInvalidStatusLines() throws Exception {
		try (ServerSocket fakeProxy = new ServerSocket(0)) {
			startFakeProxy(fakeProxy, "SOMETHING 200 OK\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
			final Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", fakeProxy.getLocalPort()));
			assertFalse(NetworkUtilities.testConnection("example.invalid", 443, 2000, proxy));
		}
		try (ServerSocket fakeProxy = new ServerSocket(0)) {
			startFakeProxy(fakeProxy, "HTTP/1.1\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
			final Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", fakeProxy.getLocalPort()));
			assertFalse(NetworkUtilities.testConnection("example.invalid", 443, 2000, proxy));
		}
	}

	@Test
	public void testProxyClosingConnectionBeforeStatusLine() throws Exception {
		try (ServerSocket fakeProxy = new ServerSocket(0)) {
			startFakeProxy(fakeProxy, "HTTP/1.1 200".getBytes(StandardCharsets.US_ASCII));
			final Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", fakeProxy.getLocalPort()));
			final Exception exception = assertThrows(Exception.class, () -> NetworkUtilities.testConnection("example.invalid", 443, 2000, proxy));
			assertTrue(exception.getMessage().contains("connection was closed before a complete status line"), exception.getMessage());
		}
	}

	@Test
	public void testProxyStatusLineTooLong() throws Exception {
		try (ServerSocket fakeProxy = new ServerSocket(0)) {
			startFakeProxy(fakeProxy, ("HTTP/1.1 200 " + "x".repeat(2000) + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
			final Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", fakeProxy.getLocalPort()));
			final Exception exception = assertThrows(Exception.class, () -> NetworkUtilities.testConnection("example.invalid", 443, 2000, proxy));
			assertTrue(exception.getMessage().contains("exceeds maximum allowed length"), exception.getMessage());
		}
	}

	// ---------------------------------------------------------------- ping

	@Test
	public void testPingHttpAndHttps() throws Exception {
		final HttpServer httpServer = TestTlsSupport.startHttpServer(exchange -> TestTlsSupport.respond(exchange, 200, "pong"));
		try {
			assertTrue(NetworkUtilities.ping("http://localhost:" + httpServer.getAddress().getPort() + "/some/path", null));
			assertTrue(NetworkUtilities.ping("HTTP://localhost:" + httpServer.getAddress().getPort(), Proxy.NO_PROXY));
		} finally {
			httpServer.stop(0);
		}

		// The self-signed certificate is not trusted by the system truststore, so the TLS connection fails
		final HttpsServer httpsServer = TestTlsSupport.startHttpsServer(exchange -> TestTlsSupport.respond(exchange, 200, "pong"));
		try {
			assertFalse(NetworkUtilities.ping("https://localhost:" + httpsServer.getAddress().getPort() + "/", null));
			assertFalse(NetworkUtilities.ping("https://localhost:" + httpsServer.getAddress().getPort() + "/", Proxy.NO_PROXY));
		} finally {
			httpsServer.stop(0);
		}

		final int closedPort = findClosedPort();
		assertFalse(NetworkUtilities.ping("http://127.0.0.1:" + closedPort + "/", Proxy.NO_PROXY));
	}

	@Test
	public void testPingHosts() {
		// InetAddress.isReachable() for loopback succeeds (ICMP, or a refused TCP echo connection)
		assertTrue(NetworkUtilities.ping("127.0.0.1", null));
		assertFalse(NetworkUtilities.ping("unknown-host-for-test.invalid", null));
	}

	// ---------------------------------------------------------------- MAC address / Wake-on-LAN

	@Test
	public void testMacAddressParsing() {
		final byte[] expected = { 0x00, 0x1A, 0x2B, 0x3C, 0x4D, (byte) 0x5E };
		assertArrayEquals(expected, NetworkUtilities.getMacAddressBytes("00:1A:2B:3C:4D:5E"));
		assertArrayEquals(expected, NetworkUtilities.getMacAddressBytes("00-1a-2b-3c-4d-5e"));
		assertArrayEquals(expected, NetworkUtilities.getMacAddressBytes("0 1A 2B 3C 4D 5E"));

		assertThrows(IllegalArgumentException.class, () -> NetworkUtilities.getMacAddressBytes(null));
		assertThrows(IllegalArgumentException.class, () -> NetworkUtilities.getMacAddressBytes(""));
		assertThrows(IllegalArgumentException.class, () -> NetworkUtilities.getMacAddressBytes("00:1A:2B:3C:4D"));
		assertThrows(IllegalArgumentException.class, () -> NetworkUtilities.getMacAddressBytes("00:1A:2B:3C:4D:ZZ"));
		assertThrows(IllegalArgumentException.class, () -> NetworkUtilities.getMacAddressBytes("00::2B:3C:4D:5E"));
	}

	@Test
	public void testWakeOnLanPing() {
		assertFalse(NetworkUtilities.wakeOnLan("invalid"));
		// Sending a broadcast may be forbidden in restricted environments, so only the call itself is checked
		NetworkUtilities.wakeOnLan("00:1A:2B:3C:4D:5E");
	}

	@Test
	public void testCheckForNetworkConnectionAndHostName() {
		// Result depends on the machine, must not throw
		NetworkUtilities.checkForNetworkConnection();
		assertNotNull(NetworkUtilities.getHostName());
	}

	// ---------------------------------------------------------------- request string parsing

	@Test
	public void testHostnameAndProtocolFromRequestString() {
		assertNull(NetworkUtilities.getHostnameFromRequestString(null));
		assertEquals("example.com", NetworkUtilities.getHostnameFromRequestString("example.com"));
		assertEquals("example.com:8443", NetworkUtilities.getHostnameFromRequestString("https://example.com:8443/path/x"));
		assertEquals("example.com", NetworkUtilities.getHostnameFromRequestString("http://example.com"));
		assertEquals("example.com", NetworkUtilities.getHostnameFromRequestString("example.com/path"));

		assertNull(NetworkUtilities.getProtocolFromRequestString(null));
		assertNull(NetworkUtilities.getProtocolFromRequestString("example.com"));
		assertEquals("https", NetworkUtilities.getProtocolFromRequestString("HTTPS://example.com"));
	}

	// ---------------------------------------------------------------- TLS certificates

	@Test
	public void testTlsServerCertificates() throws Exception {
		final HttpsServer httpsServer = TestTlsSupport.startHttpsServer(exchange -> TestTlsSupport.respond(exchange, 200, "certificate test"));
		try {
			final int port = httpsServer.getAddress().getPort();

			final List<X509Certificate> certificates = NetworkUtilities.getTlsServerCertificates("localhost", port, null, true);
			assertEquals(1, certificates.size());
			assertEquals(TestTlsSupport.getLocalhostCertificate(), certificates.get(0));

			assertEquals(TestTlsSupport.getLocalhostCertificate(), NetworkUtilities.getTlsServerCertificates("localhost", port, Proxy.NO_PROXY, true).get(0));

			// With certificate check the self-signed certificate is rejected
			assertThrows(Exception.class, () -> NetworkUtilities.getTlsServerCertificates("localhost", port));
			assertThrows(Exception.class, () -> NetworkUtilities.getTlsServerCertificates("localhost", port, Proxy.NO_PROXY, false));
		} finally {
			httpsServer.stop(0);
		}
	}

	@Test
	public void testOpenHttpsDataInputStreamWithPemCertificate() throws Exception {
		assertThrows(Exception.class, () -> NetworkUtilities.openHttpsDataInputStreamWithPemCertificate(null, null));
		assertThrows(Exception.class, () -> NetworkUtilities.openHttpsDataInputStreamWithPemCertificate("http://localhost/", null));

		final HttpsServer httpsServer = TestTlsSupport.startHttpsServer(exchange -> {
			// URLConnection.getContent() needs a content type to select a content handler
			exchange.getResponseHeaders().add("Content-Type", "text/plain");
			TestTlsSupport.respond(exchange, 200, "pinned content");
		});
		try {
			final String url = "https://localhost:" + httpsServer.getAddress().getPort() + "/";
			try (FileInputStream pemInputStream = new FileInputStream(TestTlsSupport.getLocalhostPemFile());
					InputStream dataInputStream = NetworkUtilities.openHttpsDataInputStreamWithPemCertificate(url, pemInputStream)) {
				assertEquals("pinned content", new String(dataInputStream.readAllBytes(), StandardCharsets.UTF_8));
			}

			// A different certificate is not trusted
			try (FileInputStream otherPemInputStream = new FileInputStream(TestTlsSupport.getOtherPemFile())) {
				assertThrows(Exception.class, () -> NetworkUtilities.openHttpsDataInputStreamWithPemCertificate(url, otherPemInputStream));
			}
		} finally {
			httpsServer.stop(0);
		}
	}

	// ---------------------------------------------------------------- validation

	@Test
	public void testDomainAndHostnameValidation() {
		assertTrue(NetworkUtilities.isValidDomain("example.com"));
		assertTrue(NetworkUtilities.isValidDomain("sub-domain.example.co.uk"));
		assertTrue(NetworkUtilities.isValidDomain("münchen.de"));
		assertFalse(NetworkUtilities.isValidDomain("localhost"));
		assertFalse(NetworkUtilities.isValidDomain("printer.LOCAL"));
		assertFalse(NetworkUtilities.isValidDomain("-bad.example.com"));
		assertFalse(NetworkUtilities.isValidDomain("example.c0m"));
		assertFalse(NetworkUtilities.isValidDomain("a..b.com"));
		assertFalse(NetworkUtilities.isValidDomain("x".repeat(64) + ".com"));
		assertTrue(NetworkUtilities.isValidHostname("www.example.org"));
		assertFalse(NetworkUtilities.isValidHostname("no_underscore.example.org"));
	}

	@Test
	public void testEmailValidation() {
		assertTrue(NetworkUtilities.isValidEmail("john.doe@example.com"));
		assertTrue(NetworkUtilities.isValidEmail(" \"quoted user\"@example.com "));
		assertTrue(NetworkUtilities.isValidEmail("o'neil@example.com"));
		assertFalse(NetworkUtilities.isValidEmail("no-at-sign.example.com"));
		assertFalse(NetworkUtilities.isValidEmail("john..doe@example.com"));
		assertFalse(NetworkUtilities.isValidEmail("john doe@example.com"));
		assertFalse(NetworkUtilities.isValidEmail("john@.example.com"));
		assertFalse(NetworkUtilities.isValidEmail("john@localhost"));

		assertTrue(NetworkUtilities.isValidUser("john.doe"));
		assertFalse(NetworkUtilities.isValidUser("john(doe)"));
	}

	@Test
	public void testOnlineHostnameAndUriValidation() {
		assertTrue(NetworkUtilities.isValidHostnameOnline("localhost"));
		assertTrue(NetworkUtilities.isValidHostnameOnline("127.0.0.1"));
		assertFalse(NetworkUtilities.isValidHostnameOnline("unknown-host-for-test.invalid"));

		assertTrue(NetworkUtilities.isValidUri("https://example.com/path?x=1#y"));
		assertTrue(NetworkUtilities.isValidUri("relative/path"));
		assertFalse(NetworkUtilities.isValidUri("http://exa mple.com"));
		assertFalse(NetworkUtilities.isValidUri(null));
	}

	@Test
	public void testIpValidationEdgeCases() {
		assertTrue(NetworkUtilities.isValidIpV6("::"));
		assertTrue(NetworkUtilities.isValidIpV6("::1"));
		assertTrue(NetworkUtilities.isValidIpV6("fe80::7:8%eth0"));
		assertTrue(NetworkUtilities.isValidIpV6("2001:db8:3:4::192.0.2.33"));
		assertFalse(NetworkUtilities.isValidIpV6("12345::1"));
		assertFalse(NetworkUtilities.isValidIpV4("1.2.3.4.5"));
		assertFalse(NetworkUtilities.isValidIpV4("a.b.c.d"));
	}

	// ---------------------------------------------------------------- string helpers

	@Test
	public void testStringHelpers() {
		assertTrue(NetworkUtilities.isEmpty(null));
		assertTrue(NetworkUtilities.isEmpty(""));
		assertFalse(NetworkUtilities.isEmpty(" "));
		assertTrue(NetworkUtilities.isNotEmpty(" "));
		assertFalse(NetworkUtilities.isNotEmpty(null));

		assertTrue(NetworkUtilities.isBlank(null));
		assertTrue(NetworkUtilities.isBlank(""));
		assertTrue(NetworkUtilities.isBlank(" \t"));
		assertFalse(NetworkUtilities.isBlank(" x "));
		assertTrue(NetworkUtilities.isNotBlank("x"));
		assertFalse(NetworkUtilities.isNotBlank("  "));

		assertTrue(NetworkUtilities.endsWithIgnoreCase(null, null));
		final String same = "abc";
		assertTrue(NetworkUtilities.endsWithIgnoreCase(same, same));
		assertFalse(NetworkUtilities.endsWithIgnoreCase(null, "c"));
		assertFalse(NetworkUtilities.endsWithIgnoreCase("abc", null));
		assertTrue(NetworkUtilities.endsWithIgnoreCase("ABC", "bc"));
		assertFalse(NetworkUtilities.endsWithIgnoreCase("abc", "x"));
	}

	@Test
	public void testCopy() throws Exception {
		final byte[] data = new byte[10000];
		for (int i = 0; i < data.length; i++) {
			data[i] = (byte) (i * 7);
		}
		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		assertEquals(data.length, NetworkUtilities.copy(new ByteArrayInputStream(data), outputStream));
		assertArrayEquals(data, outputStream.toByteArray());
		assertEquals(0, NetworkUtilities.copy(new ByteArrayInputStream(new byte[0]), new ByteArrayOutputStream()));
	}

	@Test
	public void testHostnamePatternWithSpecialCharacters() {
		assertTrue(NetworkUtilities.hostnamePatternMatches("my-host_1.example.com", "my-host_1.*"));
		assertFalse(NetworkUtilities.hostnamePatternMatches("myxhost.example.com", "my.host.*"));
		assertTrue(NetworkUtilities.hostnamePatternMatches("anything", "*"));
	}
}
