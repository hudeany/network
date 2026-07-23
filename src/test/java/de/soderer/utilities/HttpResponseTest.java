package de.soderer.utilities;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import de.soderer.network.HttpResponse;

@SuppressWarnings("static-method")
public class HttpResponseTest {
	@Test
	public void testHeadersAndCookiesAreUnmodifiable() {
		final Map<String, String> headers = new HashMap<>();
		headers.put("Content-Type", "text/plain");
		final Map<String, String> cookies = new HashMap<>();
		cookies.put("sessionId", "abc123");

		final HttpResponse response = new HttpResponse("127.0.0.1", 200, "OK", "body", "text/plain", headers, cookies);

		assertEquals("text/plain", response.getHeaders().get("Content-Type"));
		assertEquals("abc123", response.getCookies().get("sessionId"));

		try {
			response.getHeaders().put("Injected", "value");
			fail("Expected UnsupportedOperationException when mutating headers via the getter");
		} catch (@SuppressWarnings("unused") final UnsupportedOperationException e) {
			// expected
		}

		try {
			response.getCookies().put("injected", "value");
			fail("Expected UnsupportedOperationException when mutating cookies via the getter");
		} catch (@SuppressWarnings("unused") final UnsupportedOperationException e) {
			// expected
		}

		// the original caller-supplied maps are untouched by the wrapping, so mutating those
		// directly (as opposed to through the getters) still works as before
		headers.put("X-Extra", "1");
		assertEquals("1", response.getHeaders().get("X-Extra"));
	}

	@Test
	public void testConstructorWithoutIpAddressStillWrapsMapsAndLeavesIpAddressNull() {
		final Map<String, String> headers = new HashMap<>();
		headers.put("X-Test", "1");

		final HttpResponse response = new HttpResponse(404, "Not Found", "missing", "text/plain", headers, new HashMap<>());

		assertNull(response.getIpAddress());
		try {
			response.getHeaders().put("Injected", "value");
			fail("Expected UnsupportedOperationException when mutating headers via the getter");
		} catch (@SuppressWarnings("unused") final UnsupportedOperationException e) {
			// expected
		}
	}
}
