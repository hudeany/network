package de.soderer.network;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Tests the strict proxy URL helpers of {@link HttpUtilities}.
 */
@SuppressWarnings("static-method")
public class HttpUtilitiesProxyTest {
	@Test
	public void testCreateProxy() {
		assertNull(HttpUtilities.createProxy(null));
		assertNull(HttpUtilities.createProxy("  "));
		assertSame(Proxy.NO_PROXY, HttpUtilities.createProxy("none"));
		assertSame(Proxy.NO_PROXY, HttpUtilities.createProxy(" DIRECT "));

		final Proxy proxy = HttpUtilities.createProxy("http://127.0.0.1:3128/");
		assertEquals(Proxy.Type.HTTP, proxy.type());
		assertEquals(3128, ((InetSocketAddress) proxy.address()).getPort());
		assertEquals("127.0.0.1", ((InetSocketAddress) proxy.address()).getHostString());
		assertEquals(8080, ((InetSocketAddress) HttpUtilities.createProxy("127.0.0.1:8080").address()).getPort());
	}

	@Test
	public void testValidateProxyUrl() {
		assertDoesNotThrow(() -> HttpUtilities.validateProxyUrl(null));
		assertDoesNotThrow(() -> HttpUtilities.validateProxyUrl("none"));
		assertDoesNotThrow(() -> HttpUtilities.validateProxyUrl("proxy.example.com:3128"));
		for (final String invalidProxyUrl : new String[] { "proxy.example.com", "socks://proxy:1080", "http://user:pw@proxy:3128", "http://proxy:3128/path",
				"http://proxy:3128?x=1", "http://proxy:0", "http://proxy:70000", "http://:3128", "http://pro xy:3128" }) {
			assertThrows(IllegalArgumentException.class, () -> HttpUtilities.validateProxyUrl(invalidProxyUrl), invalidProxyUrl);
		}
	}

	@Test
	public void testResolveProxy() {
		final URI targetUri = URI.create("https://example.com/");
		assertSame(Proxy.NO_PROXY, HttpUtilities.resolveProxy("direct", targetUri));
		assertEquals(4711, ((InetSocketAddress) HttpUtilities.resolveProxy("127.0.0.1:4711", targetUri).address()).getPort());

		final ProxySelector previousProxySelector = ProxySelector.getDefault();
		final Proxy systemProxy = new Proxy(Proxy.Type.HTTP, InetSocketAddress.createUnresolved("system-proxy", 3128));
		try {
			ProxySelector.setDefault(new ProxySelector() {
				@Override
				public List<Proxy> select(final URI uri) {
					return List.of(systemProxy);
				}

				@Override
				public void connectFailed(final URI uri, final SocketAddress socketAddress, final IOException e) {
					// Not needed
				}
			});
			assertSame(systemProxy, HttpUtilities.resolveProxy(null, targetUri));
			assertSame(systemProxy, HttpUtilities.resolveProxy("", targetUri));

			ProxySelector.setDefault(null);
			assertSame(Proxy.NO_PROXY, HttpUtilities.resolveProxy(null, targetUri));
		} finally {
			ProxySelector.setDefault(previousProxySelector);
		}
	}
}
