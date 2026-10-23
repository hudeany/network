package de.soderer.utilities;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;

import de.soderer.network.HttpMethod;
import de.soderer.network.HttpRequest;
import de.soderer.network.HttpRequest.UploadFileAttachment;

/**
 * Tests for the builder methods of {@link HttpRequest} and the error paths of
 * {@link HttpRequest#parseHttpRequestData(InputStream, int, int, int)}.
 */
@SuppressWarnings("static-method")
public class HttpRequestTest {
	private static HttpRequest parse(final String requestData) throws IOException {
		return HttpRequest.parseHttpRequestData(new ByteArrayInputStream(requestData.getBytes(StandardCharsets.ISO_8859_1)), 5000);
	}

	private static void assertParseFails(final String requestData, final String expectedMessagePart) {
		final IOException exception = assertThrows(IOException.class, () -> parse(requestData));
		assertTrue(exception.getMessage().contains(expectedMessagePart), "Unexpected message: " + exception.getMessage());
	}

	// ---------------------------------------------------------------- builder

	@Test
	public void testConstructorsAndBasics() throws Exception {
		assertThrows(Exception.class, () -> new HttpRequest(" "));
		assertThrows(Exception.class, () -> new HttpRequest(HttpMethod.GET, null));

		final HttpRequest defaultPost = new HttpRequest("example.com/path");
		assertSame(HttpMethod.POST, defaultPost.getRequestMethod());
		assertEquals("example.com/path", defaultPost.getUrl());
		assertEquals("https://example.com/path", defaultPost.getUrlWithProtocol());
		assertEquals("POST example.com/path", defaultPost.toString());

		final HttpRequest nullMethod = new HttpRequest(null, "HTTP://example.com");
		assertSame(HttpMethod.GET, nullMethod.getRequestMethod());
		assertEquals("HTTP://example.com", nullMethod.getUrlWithProtocol());
		assertEquals("https://example.com", new HttpRequest(HttpMethod.GET, "https://example.com").getUrlWithProtocol());

		assertEquals(StandardCharsets.UTF_8, defaultPost.getEncoding());
		defaultPost.setEncoding(StandardCharsets.ISO_8859_1);
		assertEquals(StandardCharsets.ISO_8859_1, defaultPost.getEncoding());
		defaultPost.setEncoding(null);
		assertEquals(StandardCharsets.UTF_8, defaultPost.getEncoding());

		defaultPost.setConnectionTimeoutMillis(123).setReadTimeoutMillis(456);
		assertEquals(123, defaultPost.getConnectTimeoutMillis());
		assertEquals(456, defaultPost.getReadTimeoutMillis());

		assertEquals(HttpRequest.DEFAULT_MAX_REDIRECTS, defaultPost.setFollowRedirects(true).getMaxRedirects());
		assertTrue(defaultPost.isFollowRedirects());
		assertEquals(0, defaultPost.setFollowRedirects(false).getMaxRedirects());
		assertEquals(-1, defaultPost.setMaxRedirects(-1).getMaxRedirects());
		assertTrue(defaultPost.isFollowRedirects());

		defaultPost.addPathParameter("p", 1);
		assertEquals(1, defaultPost.getPathParameterData().get("p"));
	}

	@Test
	public void testDuplicateSpecialHeadersAreRejected() throws Exception {
		final HttpRequest request = new HttpRequest(HttpMethod.GET, "https://example.com");
		request.addUserAgentHeader("agent");
		assertThrows(Exception.class, () -> request.addUserAgentHeader("other"));
		request.addBasicAuthenticationHeader("u", "p");
		assertThrows(Exception.class, () -> request.addBasicAuthenticationHeader("u", "p"));
		// header names are case insensitive
		assertEquals("agent", request.getHeaders().get("user-agent"));
	}

	@Test
	public void testBodyKindsAreMutuallyExclusive() throws Exception {
		final InputStream stream = new ByteArrayInputStream(new byte[0]);

		final HttpRequest withBody = new HttpRequest("https://example.com").setRequestBody("body");
		assertThrows(Exception.class, () -> withBody.addPostParameter("a", "1"));
		assertThrows(Exception.class, () -> withBody.addUploadFileData("f", "f.txt", new byte[0]));
		assertThrows(Exception.class, () -> withBody.setRequestBodyContentStream(stream));
		assertEquals("body", withBody.getRequestBody());

		final HttpRequest withStream = new HttpRequest("https://example.com").setRequestBodyContentStream(stream);
		assertThrows(Exception.class, () -> withStream.addPostParameter("a", "1"));
		assertThrows(Exception.class, () -> withStream.addUploadFileData("f", "f.txt", new byte[0]));
		assertThrows(Exception.class, () -> withStream.setRequestBody("body"));
		assertSame(stream, withStream.getRequestBodyContentStream());

		final HttpRequest withPostParameter = new HttpRequest("https://example.com").addPostParameter("a", "1");
		assertThrows(Exception.class, () -> withPostParameter.setRequestBody("body"));
		assertThrows(Exception.class, () -> withPostParameter.setRequestBodyContentStream(stream));

		final HttpRequest withUpload = new HttpRequest("https://example.com").addUploadFileData("f", "f.txt", new byte[0]);
		assertThrows(Exception.class, () -> withUpload.setRequestBody("body"));
		assertThrows(Exception.class, () -> withUpload.setRequestBodyContentStream(stream));
	}

	@Test
	public void testDownloadKindsAreMutuallyExclusive() throws Exception {
		final ByteArrayOutputStream stream = new ByteArrayOutputStream();
		final File file = new File("download.txt");

		final HttpRequest withStream = new HttpRequest("https://example.com").setDownloadStream(stream);
		assertThrows(Exception.class, () -> withStream.setDownloadFile(file));
		assertThrows(Exception.class, () -> withStream.setDownloadTarget(file));
		assertSame(stream, withStream.getDownloadStream());

		final HttpRequest withFile = new HttpRequest("https://example.com").setDownloadFile(file);
		assertThrows(Exception.class, () -> withFile.setDownloadStream(stream));
		assertThrows(Exception.class, () -> withFile.setDownloadTarget(file));
		assertSame(file, withFile.getDownloadFile());

		final HttpRequest withTarget = new HttpRequest("https://example.com").setDownloadTarget(file);
		assertThrows(Exception.class, () -> withTarget.setDownloadStream(stream));
		assertThrows(Exception.class, () -> withTarget.setDownloadFile(file));
		assertSame(file, withTarget.getDownloadTarget());
	}

	@Test
	public void testUploadFileAttachmentSetters() throws Exception {
		final HttpRequest request = new HttpRequest("https://example.com").addUploadFileData("field", "name.txt", new byte[] { 1 });
		final UploadFileAttachment attachment = request.getUploadFileAttachments().get(0);
		assertEquals("field", attachment.getHtmlInputName());
		assertEquals("name.txt", attachment.getFileName());
		assertArrayEquals(new byte[] { 1 }, attachment.getData());

		assertSame(attachment, attachment.setHtmlInputName("other").setFileName("other.bin").setData(new byte[] { 2, 3 }));
		assertEquals("other", attachment.getHtmlInputName());
		assertEquals("other.bin", attachment.getFileName());
		assertArrayEquals(new byte[] { 2, 3 }, attachment.getData());
	}

	@Test
	public void testCancel() throws Exception {
		final HttpRequest request = new HttpRequest(HttpMethod.GET, "http://localhost/");
		assertNull(request.getHttpURLConnection());
		assertDoesNotThrow(request::cancel);

		// A subclass can set the connection (protected setter), cancel disconnects it
		final HttpURLConnection connection = (HttpURLConnection) URI.create("http://localhost/").toURL().openConnection(Proxy.NO_PROXY);
		final HttpRequest subclassedRequest = new HttpRequest(HttpMethod.GET, "http://localhost/") {
			{
				setHttpURLConnection(connection);
			}
		};
		assertSame(connection, subclassedRequest.getHttpURLConnection());
		assertDoesNotThrow(subclassedRequest::cancel);
	}

	// ---------------------------------------------------------------- parser: successful variants

	@Test
	public void testParseFormBodyCookiesAndQuery() throws Exception {
		final String body = "a=1&b=%C3%A4&flag&&c=";
		final HttpRequest request = parse("post /form?q=1&q=2&empty HTTP/1.1\r\n"
				+ "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n"
				+ "Cookie: a=1; ; noValue; b = 2 \r\n"
				+ "X-Multi: 1\r\n"
				+ "X-Multi: 2\r\n"
				+ "Content-Length: " + body.length() + "\r\n\r\n" + body);

		assertSame(HttpMethod.POST, request.getRequestMethod());
		assertEquals("/form?q=1&q=2&empty", request.getUrl());
		assertEquals(List.of("1", "2"), request.getUrlParameters().get("q"));
		assertEquals(List.of(""), request.getUrlParameters().get("empty"));
		assertEquals("1, 2", request.getHeaders().get("x-multi"));
		assertEquals("1", request.getCookieData().get("a"));
		assertEquals("2", request.getCookieData().get("b"));
		assertEquals(2, request.getCookieData().size());
		assertEquals(List.of("1"), request.getPostParameters().get("a"));
		assertEquals(List.of("ä"), request.getPostParameters().get("b"));
		assertEquals(List.of(""), request.getPostParameters().get("flag"));
		assertEquals(List.of(""), request.getPostParameters().get("c"));
	}

	@Test
	public void testParseTextBodyCharsets() throws Exception {
		final byte[] latin1Body = "äö".getBytes(StandardCharsets.ISO_8859_1);
		final String latin1Request = "PUT /t HTTP/1.1\r\nContent-Type: text/plain; charset=\"ISO-8859-1\"; format=flowed\r\nContent-Length: " + latin1Body.length + "\r\n\r\n";
		final ByteArrayOutputStream data = new ByteArrayOutputStream();
		data.write(latin1Request.getBytes(StandardCharsets.ISO_8859_1));
		data.write(latin1Body);
		assertEquals("äö", HttpRequest.parseHttpRequestData(new ByteArrayInputStream(data.toByteArray()), 5000).getRequestBody());

		// Unknown charset falls back to the request encoding (UTF-8)
		final String utf8Body = "ä";
		final byte[] utf8Bytes = utf8Body.getBytes(StandardCharsets.UTF_8);
		final ByteArrayOutputStream unknownCharsetData = new ByteArrayOutputStream();
		unknownCharsetData.write(("PUT /t HTTP/1.1\r\nContent-Type: text/plain; charset=no-such-charset\r\nContent-Length: " + utf8Bytes.length + "\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
		unknownCharsetData.write(utf8Bytes);
		assertEquals(utf8Body, HttpRequest.parseHttpRequestData(new ByteArrayInputStream(unknownCharsetData.toByteArray()), 5000).getRequestBody());

		// No content type at all
		assertEquals("plain", parse("PUT /t HTTP/1.1\r\nContent-Length: 5\r\n\r\nplain").getRequestBody());
		// Content type without charset
		assertEquals("{}", parse("PUT /t HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}").getRequestBody());
		// No body
		assertNull(parse("GET / HTTP/1.1\r\n\r\n").getRequestBody());
		// Empty body with Content-Length 0
		assertNull(parse("POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n").getRequestBody());
	}

	@Test
	public void testParseChunkedBodyWithExtensionsAndTrailers() throws Exception {
		final HttpRequest request = parse("POST / HTTP/1.1\r\nTransfer-Encoding: gzip, Chunked\r\n\r\n"
				+ "3;ext=1\r\nabc\r\n"
				+ "2\r\nde\r\n"
				+ "0\r\nTrailer-Header: x\r\n\r\n");
		assertEquals("abcde", request.getRequestBody());
	}

	@Test
	public void testParseMultipartWithQuotedBoundaryAndEscapes() throws Exception {
		final String body = "--BND\r\n"
				+ "Content-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n"
				+ "--BND\r\n"
				+ "Ignored header line without colon\r\n"
				+ "Content-Type: text/plain\r\n"
				+ "Content-Disposition: form-data; name=\"fi\\\"le\"; filename=\"a\\\\b.txt\"\r\n\r\ncontent\r\n"
				+ "--BND--\r\n";
		final HttpRequest request = parse("POST / HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=\"BND\"\r\nContent-Length: " + body.length() + "\r\n\r\n" + body);
		assertEquals(List.of("value"), request.getPostParameters().get("field"));
		assertEquals("fi\"le", request.getUploadFileAttachments().get(0).getHtmlInputName());
		assertEquals("a\\b.txt", request.getUploadFileAttachments().get(0).getFileName());
		assertEquals("content", new String(request.getUploadFileAttachments().get(0).getData(), StandardCharsets.UTF_8));
	}

	// ---------------------------------------------------------------- parser: errors

	@Test
	public void testParseArgumentValidation() {
		assertThrows(IllegalArgumentException.class, () -> HttpRequest.parseHttpRequestData(null, 1000));
		assertThrows(IllegalArgumentException.class, () -> HttpRequest.parseHttpRequestData(new ByteArrayInputStream(new byte[0]), 0));
	}

	@Test
	public void testParseInvalidRequestLines() {
		assertParseFails("", "Unexpected end of stream while reading HTTP headers");
		assertParseFails("GET / HTTP/1.1\r\n", "Unexpected end of stream");
		assertParseFails("\r\n\r\n", "Empty or invalid HTTP request");
		assertParseFails("GET /\r\n\r\n", "Invalid HTTP request line");
		assertParseFails("BREW / HTTP/1.1\r\n\r\n", "Unsupported HTTP method");
		assertParseFails("GET / HTTP/1.1\r\nNoColon\r\n\r\n", "Invalid header line");
		assertParseFails("GET / HTTP/1.1\r\n: no name\r\n\r\n", "Invalid header line");
	}

	@Test
	public void testParseSizeLimits() {
		final String request = "GET / HTTP/1.1\r\nX-Long: " + "x".repeat(200) + "\r\n\r\n";
		final IOException headerTooLarge = assertThrows(IOException.class,
				() -> HttpRequest.parseHttpRequestData(new ByteArrayInputStream(request.getBytes(StandardCharsets.ISO_8859_1)), 5000, 100, 1000));
		assertTrue(headerTooLarge.getMessage().contains("exceeds maximum allowed size"));

		final String bodyRequest = "POST / HTTP/1.1\r\nContent-Length: 20\r\n\r\n" + "y".repeat(20);
		final IOException bodyTooLarge = assertThrows(IOException.class,
				() -> HttpRequest.parseHttpRequestData(new ByteArrayInputStream(bodyRequest.getBytes(StandardCharsets.ISO_8859_1)), 5000, 1000, 10));
		assertTrue(bodyTooLarge.getMessage().contains("exceeds maximum allowed body size"));

		final String chunkedRequest = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n12345678\r\n8\r\n12345678\r\n0\r\n\r\n";
		final IOException chunkedTooLarge = assertThrows(IOException.class,
				() -> HttpRequest.parseHttpRequestData(new ByteArrayInputStream(chunkedRequest.getBytes(StandardCharsets.ISO_8859_1)), 5000, 1000, 10));
		assertTrue(chunkedTooLarge.getMessage().contains("Chunked body exceeds"));
	}

	@Test
	public void testParseInvalidContentLength() {
		assertParseFails("POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n", "Invalid Content-Length header");
		assertParseFails("POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n", "Negative Content-Length");
		assertParseFails("POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort", "Unexpected end of stream while reading HTTP body");
		assertParseFails("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n", "both Transfer-Encoding");
	}

	@Test
	public void testParseInvalidChunks() {
		assertParseFails("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nxyz\r\n", "Invalid chunk size line");
		assertParseFails("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\n", "Negative chunk size");
		assertParseFails("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXY", "Malformed chunk terminator");
		assertParseFails("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3", "Unexpected end of stream while reading line");
		assertParseFails("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" + "1".repeat(9000), "Line exceeds maximum allowed length");
	}

	@Test
	public void testParseInvalidMultipart() {
		final String missingBoundary = "x";
		assertParseFails("POST / HTTP/1.1\r\nContent-Type: multipart/form-data\r\nContent-Length: 1\r\n\r\n" + missingBoundary, "Missing boundary");

		final String noDelimiter = "no delimiter here";
		assertParseFails("POST / HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: " + noDelimiter.length() + "\r\n\r\n" + noDelimiter,
				"Multipart boundary not found");

		final String unterminated = "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nvalue";
		assertParseFails("POST / HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: " + unterminated.length() + "\r\n\r\n" + unterminated,
				"Unterminated multipart section");

		final String noSeparator = "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n--B--\r\n";
		assertParseFails("POST / HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: " + noSeparator.length() + "\r\n\r\n" + noSeparator,
				"missing header/body separator");

		final String noName = "--B\r\nContent-Disposition: form-data\r\n\r\nvalue\r\n--B--\r\n";
		assertParseFails("POST / HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: " + noName.length() + "\r\n\r\n" + noName,
				"without a 'name'");
	}

	@Test
	public void testParseTimeout() {
		// A stream that delivers one byte per read slowly runs into the total deadline
		final InputStream slowStream = new InputStream() {
			private final byte[] data = "GET / HTTP/1.1\r\nX: 1\r\n".getBytes(StandardCharsets.ISO_8859_1);
			private int position = 0;

			@Override
			public int read() throws IOException {
				try {
					Thread.sleep(20);
				} catch (final InterruptedException e) {
					Thread.currentThread().interrupt();
					throw new IOException(e);
				}
				return position < data.length ? data[position++] : 'x';
			}
		};
		assertThrows(SocketTimeoutException.class, () -> HttpRequest.parseHttpRequestData(slowStream, 100));
	}

	@Test
	public void testRedirectsAreNotFollowedByDefault() throws Exception {
		final HttpRequest request = new HttpRequest(HttpMethod.GET, "https://example.com");
		assertFalse(request.isFollowRedirects());
		assertEquals(0, request.getMaxRedirects());
		assertTrue(request.setMaxRedirects(3).isFollowRedirects());
	}
}
