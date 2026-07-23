package de.soderer.utilities;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.Test;

import de.soderer.network.HttpMethod;
import de.soderer.network.HttpRequest;

@SuppressWarnings("static-method")
public class HttpRequestParsingTest {
	private static InputStream buildRawRequest(final String requestLine, final List<String> headerLines, final String body) {
		final byte[] bodyBytes = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
		final StringBuilder raw = new StringBuilder();
		raw.append(requestLine).append("\r\n");
		for (final String headerLine : headerLines) {
			raw.append(headerLine).append("\r\n");
		}
		raw.append("\r\n");
		final byte[] headerBytes = raw.toString().getBytes(StandardCharsets.US_ASCII);
		final byte[] fullRequest = new byte[headerBytes.length + bodyBytes.length];
		System.arraycopy(headerBytes, 0, fullRequest, 0, headerBytes.length);
		System.arraycopy(bodyBytes, 0, fullRequest, headerBytes.length, bodyBytes.length);
		return new ByteArrayInputStream(fullRequest);
	}

	@Test
	public void testHeaderNamesAreCaseInsensitive() throws Exception {
		final String body = "a=1&b=2";
		final InputStream requestStream = buildRawRequest(
				"POST /test HTTP/1.1",
				List.of(
						"content-type: application/x-www-form-urlencoded",
						"content-length: " + body.getBytes(StandardCharsets.UTF_8).length),
				body);

		final HttpRequest request = HttpRequest.parseHttpRequestData(requestStream, 5000);

		assertEquals(HttpMethod.POST, request.getRequestMethod());
		assertEquals(List.of("1"), request.getPostParameters().get("a"));
		assertEquals(List.of("2"), request.getPostParameters().get("b"));
	}

	@Test
	public void testTransferEncodingContentLengthConflictIsRejectedRegardlessOfCase() {
		final InputStream requestStream = buildRawRequest(
				"POST /smuggle HTTP/1.1",
				List.of(
						"Transfer-Encoding: chunked",
						"content-length: 5"), // lower-case on purpose: must still be detected
				"0\r\n\r\n");

		try {
			HttpRequest.parseHttpRequestData(requestStream, 5000);
			fail("Expected an IOException for conflicting Transfer-Encoding/Content-Length headers");
		} catch (final IOException e) {
			assertTrue(e.getMessage().contains("Transfer-Encoding"));
		}
	}

	@Test
	public void testMultipleCookieHeaderLinesAreJoinedCorrectly() throws Exception {
		final InputStream requestStream = buildRawRequest(
				"GET /cookies HTTP/1.1",
				List.of(
						"Cookie: a=1",
						"Cookie: b=2"),
				null);

		final HttpRequest request = HttpRequest.parseHttpRequestData(requestStream, 5000);

		assertEquals("1", request.getCookieData().get("a"));
		assertEquals("2", request.getCookieData().get("b"));
	}

	@Test
	public void testChunkedBodyIsDecoded() throws Exception {
		final String chunkedBody = "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
		final InputStream requestStream = buildRawRequest(
				"POST /chunked HTTP/1.1",
				List.of("Transfer-Encoding: chunked"),
				chunkedBody);

		final HttpRequest request = HttpRequest.parseHttpRequestData(requestStream, 5000);

		assertEquals("Wikipedia", request.getRequestBody());
	}

	@Test
	public void testMultipartBodyIsParsedIntoFieldsAndAttachments() throws Exception {
		final String boundary = "TestBoundary123";
		final String multipartBody = "--" + boundary + "\r\n"
				+ "Content-Disposition: form-data; name=\"field1\"\r\n\r\n"
				+ "value1\r\n"
				+ "--" + boundary + "\r\n"
				+ "Content-Disposition: form-data; name=\"file1\"; filename=\"test.txt\"\r\n\r\n"
				+ "file-content\r\n"
				+ "--" + boundary + "--\r\n";

		final InputStream requestStream = buildRawRequest(
				"POST /upload HTTP/1.1",
				List.of(
						"content-type: multipart/form-data; boundary=" + boundary,
						"Content-Length: " + multipartBody.getBytes(StandardCharsets.UTF_8).length),
				multipartBody);

		final HttpRequest request = HttpRequest.parseHttpRequestData(requestStream, 5000);

		assertEquals(List.of("value1"), request.getPostParameters().get("field1"));
		assertEquals(1, request.getUploadFileAttachments().size());
		assertEquals("test.txt", request.getUploadFileAttachments().get(0).getFileName());
		assertEquals("file-content", new String(request.getUploadFileAttachments().get(0).getData(), StandardCharsets.UTF_8));
	}
}
