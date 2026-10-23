package de.soderer.utilities;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import de.soderer.network.HttpUtilities;

/**
 * Tests for the static helper methods of {@link HttpUtilities}.
 */
@SuppressWarnings("static-method")
public class HttpUtilitiesHelpersTest {
	private static Object invokePrivate(final String methodName, final Class<?>[] parameterTypes, final Object... arguments) throws Exception {
		final Method method = HttpUtilities.class.getDeclaredMethod(methodName, parameterTypes);
		method.setAccessible(true);
		return method.invoke(null, arguments);
	}

	@Test
	public void testConvertToParameterString() {
		assertNull(HttpUtilities.convertToParameterString(null, null));

		final Map<String, List<Object>> parameters = new LinkedHashMap<>();
		parameters.put("a b", new ArrayList<>(Arrays.asList("1", null)));
		parameters.put("ä", new ArrayList<>(Arrays.asList("ö")));
		assertEquals("a+b=1&a+b=&%C3%A4=%C3%B6", HttpUtilities.convertToParameterString(parameters, null));
		assertEquals("a+b=1&a+b=&%E4=%F6", HttpUtilities.convertToParameterString(parameters, StandardCharsets.ISO_8859_1));
		assertEquals("", HttpUtilities.convertToParameterString(new LinkedHashMap<>(), StandardCharsets.UTF_8));
	}

	@Test
	public void testUrlEncodeAndDecode() {
		assertEquals("a+b%26c%3D%C3%A4", HttpUtilities.urlEncode("a b&c=ä", StandardCharsets.UTF_8));
		assertEquals("a b&c=ä", HttpUtilities.urlDecode("a+b%26c%3D%C3%A4", StandardCharsets.UTF_8));
		assertThrows(IllegalArgumentException.class, () -> HttpUtilities.urlDecode("%zz", StandardCharsets.UTF_8));
	}

	@Test
	public void testCreateHtmlFormMimetypeHeader() {
		assertEquals(List.of("application/x-www-form-urlencoded"), HttpUtilities.createHtmlFormMimetypeHeader(null).get("Content-Type"));
		assertEquals(List.of("application/x-www-form-urlencoded; charset=utf-8"), HttpUtilities.createHtmlFormMimetypeHeader(StandardCharsets.UTF_8).get("Content-Type"));
	}

	@Test
	public void testAddUrlParameterWithValueTypes() {
		assertEquals("http://x/a?n=v", HttpUtilities.addUrlParameter("http://x/a", "n", "v", null));
		assertEquals("http://x/a?b=1&n+m=v+w", HttpUtilities.addUrlParameter("http://x/a?b=1", "n m", "v w", StandardCharsets.UTF_8));
		assertEquals("http://x/a?n=secret", HttpUtilities.addUrlParameter("http://x/a", "n", "secret".toCharArray(), null));
		assertEquals("http://x/a?n=s+t", HttpUtilities.addUrlParameter("http://x/a", "n", "s t".toCharArray(), StandardCharsets.UTF_8));
		assertEquals("http://x/a?n=1,null,c d", HttpUtilities.addUrlParameter("http://x/a", "n", new Object[] { 1, null, "c d" }, null));
		assertEquals("http://x/a?n=1,c+d", HttpUtilities.addUrlParameter("http://x/a", "n", new String[] { "1", "c d" }, StandardCharsets.UTF_8));
		assertEquals("http://x/a?n=null", HttpUtilities.addUrlParameter("http://x/a", "n", null, null));
		assertEquals("http://x/a?b=1&n=2#frag", HttpUtilities.addUrlParameter("http://x/a?b=1#frag", "n", 2, StandardCharsets.UTF_8));
	}

	@Test
	public void testAddPathParameter() {
		assertEquals("http://x/a;p=1", HttpUtilities.addPathParameter("http://x/a", "p=1"));
		assertEquals("http://x/a;p=1?q=2", HttpUtilities.addPathParameter("http://x/a?q=2", "p=1"));
		assertEquals("http://x/a;p=1#frag", HttpUtilities.addPathParameter("http://x/a#frag", "p=1"));
	}

	@Test
	public void testParameterFromHtmlEdgeCases() {
		assertNull(HttpUtilities.getPlainParameterFromHtml(null, "a"));
		assertNull(HttpUtilities.getPlainParameterFromHtml("   ", "a"));
		assertNull(HttpUtilities.getPlainParameterFromHtml(" b=1 ", "a"));
		assertEquals("", HttpUtilities.getPlainParameterFromHtml(" a= ", "a"));
		assertNull(HttpUtilities.getQuotedParameterFromHtml(null, "a"));
		assertNull(HttpUtilities.getQuotedParameterFromHtml("", "a"));
		assertNull(HttpUtilities.getQuotedParameterFromHtml("<x b=\"1\">", "a"));
		// regex characters in the name are matched literally
		assertNull(HttpUtilities.getQuotedParameterFromHtml("<x ab=\"1\">", "a.?"));
		assertEquals("v1", HttpUtilities.getQuotedParameterFromHtml("<x a.?  =  \"v1\">", "a.?"));
	}

	@Test
	public void testAllHttpStatusTexts() {
		final Map<Integer, String> expectedTexts = new LinkedHashMap<>();
		expectedTexts.put(200, "OK");
		expectedTexts.put(201, "Created");
		expectedTexts.put(202, "Accepted");
		expectedTexts.put(203, "Non-Authoritative Information");
		expectedTexts.put(204, "No Content");
		expectedTexts.put(205, "Reset Content");
		expectedTexts.put(206, "Partial Content");
		expectedTexts.put(300, "Multiple Choices");
		expectedTexts.put(301, "Moved Permanently");
		expectedTexts.put(302, "Found");
		expectedTexts.put(303, "See Other");
		expectedTexts.put(304, "Not Modified");
		expectedTexts.put(305, "Use Proxy");
		expectedTexts.put(307, "Temporary Redirect");
		expectedTexts.put(308, "Permanent Redirect");
		expectedTexts.put(400, "Bad Request");
		expectedTexts.put(401, "Unauthorized");
		expectedTexts.put(402, "Payment Required");
		expectedTexts.put(403, "Forbidden");
		expectedTexts.put(404, "Not Found");
		expectedTexts.put(405, "Method Not Allowed");
		expectedTexts.put(406, "Not Acceptable");
		expectedTexts.put(407, "Proxy Authentication Required");
		expectedTexts.put(408, "Request Time-Out");
		expectedTexts.put(409, "Conflict");
		expectedTexts.put(410, "Gone");
		expectedTexts.put(411, "Length Required");
		expectedTexts.put(412, "Precondition Failed");
		expectedTexts.put(413, "Request Entity Too Large");
		expectedTexts.put(414, "Request-URI Too Large");
		expectedTexts.put(415, "Unsupported Media Type");
		expectedTexts.put(500, "Internal Server Error");
		expectedTexts.put(501, "Not Implemented");
		expectedTexts.put(502, "Bad Gateway");
		expectedTexts.put(503, "Service Unavailable");
		expectedTexts.put(504, "Gateway Timeout");
		expectedTexts.put(505, "HTTP Version Not Supported");
		for (final Map.Entry<Integer, String> entry : expectedTexts.entrySet()) {
			assertEquals(entry.getValue(), HttpUtilities.getHttpStatusText(entry.getKey()), "Status " + entry.getKey());
		}
		assertEquals("Unknown Http Status Code (418)", HttpUtilities.getHttpStatusText(418));
	}

	@Test
	public void testBasicAuthenticationHeaderValue() {
		assertEquals("Basic " + Base64.getEncoder().encodeToString("ä:p:w".getBytes(StandardCharsets.UTF_8)),
				HttpUtilities.createBasicAuthenticationHeaderValue("ä", "p:w"));
	}

	@Test
	public void testGenerateBoundary() throws Exception {
		final String boundary = HttpUtilities.generateBoundary();
		assertEquals(32, boundary.length());
		assertTrue(boundary.matches("[a-zA-Z0-9]{32}"));
		assertNotEquals(boundary, HttpUtilities.generateBoundary());
	}

	@Test
	public void testProxyFromStringVariants() {
		assertSame(Proxy.NO_PROXY, HttpUtilities.getProxyFromString(null));
		assertSame(Proxy.NO_PROXY, HttpUtilities.getProxyFromString("   "));
		assertSame(Proxy.NO_PROXY, HttpUtilities.getProxyFromString("direct"));

		final InetSocketAddress defaultPort = (InetSocketAddress) HttpUtilities.getProxyFromString("proxy.invalid").address();
		assertEquals("proxy.invalid", defaultPort.getHostString());
		assertEquals(8080, defaultPort.getPort());

		final InetSocketAddress httpsPrefix = (InetSocketAddress) HttpUtilities.getProxyFromString(" HTTPS://proxy.invalid:3129 ").address();
		assertEquals("proxy.invalid", httpsPrefix.getHostString());
		assertEquals(3129, httpsPrefix.getPort());

		final Proxy ipv6WithoutPort = HttpUtilities.getProxyFromString("[::1]");
		assertEquals(Proxy.Type.HTTP, ipv6WithoutPort.type());
		assertEquals(8080, ((InetSocketAddress) ipv6WithoutPort.address()).getPort());

		assertThrows(IllegalArgumentException.class, () -> HttpUtilities.getProxyFromString("[::1:3128"));
		assertThrows(NumberFormatException.class, () -> HttpUtilities.getProxyFromString("proxy.invalid:abc"));
	}

	@Test
	public void testGetIpAddressOfUnconnectedConnection() throws Exception {
		// Unresolvable host: no headers and no address, so null is returned
		final HttpURLConnection unresolvable = (HttpURLConnection) URI.create("http://unknown-host-for-test.invalid/").toURL().openConnection(Proxy.NO_PROXY);
		unresolvable.setConnectTimeout(2000);
		assertNull(HttpUtilities.getIpAddress(unresolvable));

		// Closed port on localhost: no headers, but the host is resolved
		final int closedPort;
		try (ServerSocket serverSocket = new ServerSocket(0)) {
			closedPort = serverSocket.getLocalPort();
		}
		final HttpURLConnection closed = (HttpURLConnection) URI.create("http://127.0.0.1:" + closedPort + "/").toURL().openConnection(Proxy.NO_PROXY);
		closed.setConnectTimeout(2000);
		assertEquals("127.0.0.1", HttpUtilities.getIpAddress(closed));
	}

	@Test
	public void testSameOriginRules() throws Exception {
		final Class<?>[] types = { URI.class, URI.class };
		assertTrue((Boolean) invokePrivate("isSameOrigin", types, URI.create("https://Example.com/a"), URI.create("https://example.COM:443/b")));
		assertTrue((Boolean) invokePrivate("isSameOrigin", types, URI.create("http://example.com/a"), URI.create("http://example.com:80/b")));
		assertFalse((Boolean) invokePrivate("isSameOrigin", types, URI.create("http://example.com/a"), URI.create("https://example.com/a")));
		assertFalse((Boolean) invokePrivate("isSameOrigin", types, URI.create("https://example.com/a"), URI.create("https://example.com:8443/a")));
		assertFalse((Boolean) invokePrivate("isSameOrigin", types, URI.create("https://example.com/a"), URI.create("https://other.com/a")));
		assertFalse((Boolean) invokePrivate("isSameOrigin", types, URI.create("mailto:a@example.com"), URI.create("https://example.com/a")));
		assertFalse((Boolean) invokePrivate("isSameOrigin", types, URI.create("https://example.com/a"), URI.create("/relative")));
		// Scheme-relative URIs have a host but no scheme
		assertTrue((Boolean) invokePrivate("isSameOrigin", types, URI.create("//example.com/a"), URI.create("//example.com/b")));
	}

	@Test
	public void testDownloadFileNameResolution() throws Exception {
		final Class<?>[] types = { Map.class, String.class };
		assertEquals("download", invokePrivate("resolveDownloadFileName", types, null, null));
		assertEquals("download", invokePrivate("resolveDownloadFileName", types, Map.of("Content-Disposition", "attachment; filename=\"\""), "http://x/"));
		assertEquals("a.txt", invokePrivate("resolveDownloadFileName", types, Map.of("Content-Disposition", "attachment; filename*=UTF-8''%20"), "http://x/a.txt"));
		// Malformed percent encoding in the URL is kept literally
		assertEquals("a%zz.txt", invokePrivate("resolveDownloadFileName", types, Map.of(), "http://x/a%zz.txt"));

		final Class<?>[] sanitizeTypes = { String.class };
		assertEquals("evil.txt", invokePrivate("sanitizeDownloadFileName", sanitizeTypes, "..\\..\\evil.txt"));
		assertEquals("a_b_c_d_e_f_g_h_", invokePrivate("sanitizeDownloadFileName", sanitizeTypes, "a<b>c:d\"e|f?g*h\u0001"));
		assertEquals("name", invokePrivate("sanitizeDownloadFileName", sanitizeTypes, " name. . "));
		assertEquals("download", invokePrivate("sanitizeDownloadFileName", sanitizeTypes, "dir/"));
	}

	@Test
	public void testEncodeForCookieKeepsNull() throws Exception {
		assertNull(invokePrivate("encodeForCookie", new Class<?>[] { String.class }, (Object) null));
		assertEquals("a%3Bb%3Dc", invokePrivate("encodeForCookie", new Class<?>[] { String.class }, "a;b=c"));
	}
}
