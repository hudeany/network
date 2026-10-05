package de.soderer.utilities;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import de.soderer.network.HttpContentType;
import de.soderer.network.HttpRequest;
import de.soderer.network.HttpUtilities;
import de.soderer.network.NetworkUtilities;

/**
 * Regression tests for bugs found during the Javadoc and bug review of the network library.
 */
@SuppressWarnings("static-method")
public class NetworkRegressionTest {
	private static HttpRequest parse(final String requestData) throws IOException {
		return HttpRequest.parseHttpRequestData(new ByteArrayInputStream(requestData.getBytes(StandardCharsets.ISO_8859_1)), 2000);
	}

	@Test
	public void testChunkSizeOverflowIsRejected() {
		// A huge chunk size must not overflow the size check and allocate gigabytes
		Assertions.assertThrows(IOException.class, () -> parse("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n7FFFFFFF\r\n"));
	}

	@Test
	public void testInvalidUrlEncodingIsIOException() {
		Assertions.assertThrows(IOException.class, () -> parse("GET /?a=%zz HTTP/1.1\r\nHost: x\r\n\r\n"));
	}

	@Test
	public void testHeaderWhitespaceAndFoldingAreRejected() {
		Assertions.assertThrows(IOException.class, () -> parse("GET / HTTP/1.1\r\nTransfer-Encoding : chunked\r\n\r\n"));
		Assertions.assertThrows(IOException.class, () -> parse("GET / HTTP/1.1\r\nX: a\r\n b\r\n\r\n"));
	}

	@Test
	public void testMultipartFileNameWithSemicolon() throws IOException {
		final String body = "--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a;b.txt\"\r\n\r\ndata\r\n--B--\r\n";
		final HttpRequest request = parse("POST / HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: " + body.length() + "\r\n\r\n" + body);
		Assertions.assertEquals("a;b.txt", request.getUploadFileAttachments().get(0).getFileName());
	}

	@Test
	public void testContentTypeWithParameters() throws Exception {
		Assertions.assertEquals(HttpContentType.Json, HttpContentType.getHttpContentTypeByName("application/json ; charset=UTF-8"));
		Assertions.assertThrows(Exception.class, () -> HttpContentType.getHttpContentTypeByName(null));
	}

	@Test
	public void testAddUrlParameterWithQuestionMarkInFragment() {
		Assertions.assertEquals("http://x/a?b=1#frag?x", HttpUtilities.addUrlParameter("http://x/a#frag?x", "b=1"));
	}

	@Test
	public void testProxyFromString() {
		Assertions.assertEquals(3128, ((InetSocketAddress) HttpUtilities.getProxyFromString("http://[::1]:3128/").address()).getPort());
		Assertions.assertEquals(8081, ((InetSocketAddress) HttpUtilities.getProxyFromString("proxy:8081/").address()).getPort());
		Assertions.assertEquals(Proxy.NO_PROXY, HttpUtilities.getProxyFromString(" DIRECT "));
	}

	@Test
	public void testParameterFromHtml() {
		Assertions.assertEquals("abc", HttpUtilities.getQuotedParameterFromHtml("<input name=\"x\" value=\"abc\" >", "value"));
		Assertions.assertEquals("12", HttpUtilities.getPlainParameterFromHtml(" a.b=12 ", "a.b"));
	}

	@Test
	public void testStatusTexts() {
		Assertions.assertEquals("Found", HttpUtilities.getHttpStatusText(302));
		Assertions.assertEquals("Temporary Redirect", HttpUtilities.getHttpStatusText(307));
	}

	@Test
	public void testParameterOrderIsKept() throws Exception {
		final HttpRequest request = new HttpRequest("https://example.com")
				.addPostParameter("zeta", 1)
				.addPostParameter("alpha", 2)
				.addPostParameter("mike", 3)
				.addUrlParameter("zeta", 1)
				.addUrlParameter("alpha", 2)
				.addUrlParameter("mike", 3);
		// Parameters are sent in the order they were added
		Assertions.assertEquals("zeta=1&alpha=2&mike=3", HttpUtilities.convertToParameterString(request.getPostParameters(), StandardCharsets.UTF_8));
		Assertions.assertEquals("zeta=1&alpha=2&mike=3", HttpUtilities.convertToParameterString(request.getUrlParameters(), StandardCharsets.UTF_8));
	}

	@Test
	public void testMacAddressPartTooLong() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> NetworkUtilities.getMacAddressBytes("123:00:00:00:00:00"));
	}
}
