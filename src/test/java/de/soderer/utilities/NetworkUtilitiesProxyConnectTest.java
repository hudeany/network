package de.soderer.utilities;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

import org.junit.Test;

import de.soderer.network.NetworkUtilities;

@SuppressWarnings("static-method")
public class NetworkUtilitiesProxyConnectTest {
	@Test
	public void testHostnameWithCrlfIsRejectedBeforeAnyConnectionIsMade() {
		final Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", 1));
		try {
			NetworkUtilities.testConnection("evil.com\r\nX-Injected: 1", 443, 1000, proxy);
			fail("Expected an IllegalArgumentException for a hostname containing CR/LF");
		} catch (@SuppressWarnings("unused") final IllegalArgumentException e) {
			// expected
		} catch (final Exception e) {
			fail("Expected an IllegalArgumentException but got " + e.getClass().getSimpleName() + ": " + e.getMessage());
		}
	}

	@Test
	public void testLooseTwoHundredSubstringInAnErrorResponseIsNotTreatedAsSuccess() throws Exception {
		try (ServerSocket fakeProxy = new ServerSocket(0)) {
			startFakeProxyResponder(fakeProxy, "HTTP/1.1 502 Bad Gateway (port 5200 unreachable)\r\n\r\n");

			final Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", fakeProxy.getLocalPort()));
			final boolean result = NetworkUtilities.testConnection("example.com", 443, 2000, proxy);

			assertFalse("A '200' substring inside an unrelated status/reason must not be treated as success", result);
		}
	}

	@Test
	public void testStrictTwoHundredStatusIsTreatedAsSuccess() throws Exception {
		try (ServerSocket fakeProxy = new ServerSocket(0)) {
			startFakeProxyResponder(fakeProxy, "HTTP/1.1 200 Connection established\r\n\r\n");

			final Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", fakeProxy.getLocalPort()));
			final boolean result = NetworkUtilities.testConnection("example.com", 443, 2000, proxy);

			assertTrue(result);
		}
	}

	private static void startFakeProxyResponder(final ServerSocket fakeProxy, final String canned) {
		final Thread serverThread = new Thread(() -> {
			try (Socket client = fakeProxy.accept()) {
				// consume (and ignore) the CONNECT request line/headers sent by the client
				client.getInputStream().read(new byte[1024]);
				final OutputStream out = client.getOutputStream();
				out.write(canned.getBytes(StandardCharsets.US_ASCII));
				out.flush();
			} catch (@SuppressWarnings("unused") final IOException e) {
				// connection closed after the assertion or test end: ignore
			}
		});
		serverThread.setDaemon(true);
		serverThread.start();
	}
}
