package de.soderer.network;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * Tests of {@link HttpVersion} and of the HTTP version in {@link HttpRequest} and {@link HttpResponse}
 * without any network access.
 */
@SuppressWarnings("static-method")
public class HttpVersionTest {
	@Test
	public void testProtocolNames() {
		assertEquals("HTTP/1.0", HttpVersion.HTTP_1_0.getProtocolName());
		assertEquals("HTTP/1.1", HttpVersion.HTTP_1_1.getProtocolName());
		assertEquals("HTTP/2", HttpVersion.HTTP_2.getProtocolName());
	}

	@Test
	public void testRequestDefaultsToHttp11() throws Exception {
		assertEquals(HttpVersion.HTTP_1_1, new HttpRequest(HttpMethod.GET, "https://example.com").getHttpVersion());
	}

	@Test
	public void testSetHttpVersionReturnsRequestForChaining() throws Exception {
		final HttpRequest request = new HttpRequest(HttpMethod.GET, "https://example.com");
		assertSame(request, request.setHttpVersion(HttpVersion.HTTP_2));
		assertEquals(HttpVersion.HTTP_2, request.getHttpVersion());
	}

	@Test
	public void testSetHttpVersionNullMeansHttp11() throws Exception {
		final HttpRequest request = new HttpRequest(HttpMethod.GET, "https://example.com").setHttpVersion(HttpVersion.HTTP_2);
		request.setHttpVersion(null);
		assertEquals(HttpVersion.HTTP_1_1, request.getHttpVersion());
	}

	@Test
	public void testHttp10CannotBeRequested() throws Exception {
		final HttpRequest request = new HttpRequest(HttpMethod.GET, "https://example.com").setHttpVersion(HttpVersion.HTTP_2);
		assertThrows(IllegalArgumentException.class, () -> request.setHttpVersion(HttpVersion.HTTP_1_0));
		// A rejected value leaves the previous setting unchanged
		assertEquals(HttpVersion.HTTP_2, request.getHttpVersion());
	}

	@Test
	public void testRequestToStringShowsOnlyNonDefaultVersion() throws Exception {
		assertEquals("GET https://example.com", new HttpRequest(HttpMethod.GET, "https://example.com").toString());
		assertEquals("GET https://example.com (HTTP/2)", new HttpRequest(HttpMethod.GET, "https://example.com").setHttpVersion(HttpVersion.HTTP_2).toString());
	}

	@Test
	public void testResponseConstructorsWithoutVersionReturnNull() {
		assertNull(new HttpResponse(200, "OK", "content", "text/plain", null, null).getHttpVersion());
		assertNull(new HttpResponse("127.0.0.1", 200, "OK", "content", "text/plain", null, null).getHttpVersion());
		assertNull(new HttpResponse("127.0.0.1", 200, "OK", "content", "text/plain", null, null, 0, null, false).getHttpVersion());
		assertNull(new HttpResponse("127.0.0.1", 200, "OK", "content", "text/plain", null, null, 0, null, false, null).getHttpVersion());
	}

	@Test
	public void testResponseWithVersion() {
		final HttpResponse response = new HttpResponse("127.0.0.1", 200, "OK", "content", "text/plain", Map.of(), null, 0, null, false, null,
				HttpVersion.HTTP_2);
		assertEquals(HttpVersion.HTTP_2, response.getHttpVersion());
		assertTrue(response.toString().contains("HttpVersion: HTTP/2\n"), response.toString());
	}

	@Test
	public void testResponseToStringWithoutVersionHasNoVersionLine() {
		final HttpResponse response = new HttpResponse(200, "OK", "content", "text/plain", null, null);
		assertFalse(response.toString().contains("HttpVersion"), response.toString());
	}
}
