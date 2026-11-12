package de.soderer.network;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import de.soderer.network.utilities.CaseInsensitiveLinkedMap;

/**
 * Tests for the small value classes and enums, the case insensitive map and the Windows specific
 * helper (which runs on every OS by temporarily faking the "os.name" system property).
 */
@SuppressWarnings("static-method")
public class SmallClassesTest {
	// ---------------------------------------------------------------- HttpMethod / HttpContentType

	@Test
	public void testHttpMethodByName() throws Exception {
		for (final HttpMethod method : HttpMethod.values()) {
			assertSame(method, HttpMethod.getHttpMethodByName(method.name().toLowerCase()));
		}
		final Exception exception = assertThrows(Exception.class, () -> HttpMethod.getHttpMethodByName("BREW"));
		assertTrue(exception.getMessage().contains("BREW"));
		assertThrows(Exception.class, () -> HttpMethod.getHttpMethodByName(null));
	}

	@Test
	public void testHttpContentType() throws Exception {
		for (final HttpContentType contentType : HttpContentType.values()) {
			assertSame(contentType, HttpContentType.getHttpContentTypeByName(contentType.getStringRepresentation().toUpperCase()));
			assertEquals(contentType.getStringRepresentation(), contentType.toString());
		}
		assertThrows(Exception.class, () -> HttpContentType.getHttpContentTypeByName("image/png"));
	}

	// ---------------------------------------------------------------- HttpResponse

	@Test
	public void testHttpResponseGettersAndToString() {
		final Map<String, String> headers = new LinkedHashMap<>();
		headers.put("Content-Type", "text/plain");
		final Map<String, String> cookies = new LinkedHashMap<>();
		cookies.put("sid", "1");

		final HttpResponse response = new HttpResponse("10.0.0.1", 200, "OK", "body", "text/plain", headers, cookies, 2, "https://final", false, "/tmp/file");
		assertEquals("10.0.0.1", response.getIpAddress());
		assertEquals(200, response.getHttpCode());
		assertEquals("OK", response.getHttpCodeMessage());
		assertEquals("body", response.getContent());
		assertEquals("text/plain", response.getContentType());
		assertEquals(2, response.getRedirectCount());
		assertEquals("https://final", response.getFinalUrl());
		assertFalse(response.isCredentialsDroppedOnRedirect());
		assertEquals("/tmp/file", response.getDownloadedFilePath());

		final String description = response.toString();
		assertTrue(description.startsWith("HttpCode: 200 (OK)\n"));
		assertTrue(description.contains("Redirects: 2 -> https://final\n"));
		assertTrue(description.contains("HttpHeaders:\n\tContent-Type: text/plain\n"));
		assertTrue(description.contains("HttpCookies:\n\tsid: 1\n"));
		assertTrue(description.contains("ContentType: text/plain\n"));
		assertTrue(description.endsWith("Content: \nbody\n"));
	}

	@Test
	public void testHttpResponseWithoutOptionalData() {
		final HttpResponse response = new HttpResponse(204, null, null, null, null, null);
		assertNull(response.getHeaders());
		assertNull(response.getCookies());
		assertNull(response.getIpAddress());
		final String description = response.toString();
		assertTrue(description.startsWith("HttpCode: 204\n"));
		assertFalse(description.contains("Redirects"));
		assertFalse(description.contains("HttpHeaders"));
		assertFalse(description.contains("HttpCookies"));

		final HttpResponse emptyMaps = new HttpResponse("1.2.3.4", 200, "", "x", null, new LinkedHashMap<>(), new LinkedHashMap<>(), 1, "u", true);
		final String emptyMapsDescription = emptyMaps.toString();
		assertTrue(emptyMapsDescription.startsWith("HttpCode: 200\n"));
		assertTrue(emptyMapsDescription.contains("(credentials dropped on cross-origin redirect)"));
		assertFalse(emptyMapsDescription.contains("HttpHeaders"));
		assertFalse(emptyMapsDescription.contains("HttpCookies"));
		assertTrue(emptyMaps.isCredentialsDroppedOnRedirect());
	}

	// ---------------------------------------------------------------- CaseInsensitiveLinkedMap

	@Test
	public void testCaseInsensitiveMapConstructors() {
		final Map<String, Integer> source = new LinkedHashMap<>();
		source.put("A", 1);
		source.put("a", 2);
		source.put("B", 3);

		final CaseInsensitiveLinkedMap<Integer> copy = new CaseInsensitiveLinkedMap<>(source);
		assertEquals(2, copy.size());
		assertEquals(2, copy.get("A"));
		assertEquals(3, copy.get("b"));

		assertTrue(CaseInsensitiveLinkedMap.<String>create().isEmpty());
		assertTrue(new CaseInsensitiveLinkedMap<String>(10).isEmpty());
		assertTrue(new CaseInsensitiveLinkedMap<String>(10, 0.5f).isEmpty());

		// access order: a get moves the entry to the end
		final CaseInsensitiveLinkedMap<Integer> accessOrdered = new CaseInsensitiveLinkedMap<>(10, 0.75f, true);
		accessOrdered.put("First", 1);
		accessOrdered.put("Second", 2);
		accessOrdered.get("FIRST");
		assertEquals("second", accessOrdered.keySet().iterator().next());
		assertEquals("second", accessOrdered.entrySet().iterator().next().getKey());
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testCaseInsensitiveMapKeyConversionEverywhere() {
		final CaseInsensitiveLinkedMap<String> map = new CaseInsensitiveLinkedMap<>();
		map.put("Key", "v");
		map.put(null, "nullValue");

		assertEquals("nullValue", map.get(null));
		assertTrue(map.containsKey(null));
		// non-String keys never match
		assertFalse(map.containsKey(5));
		assertNull(map.get(5));
		map.put("5", "five");
		assertFalse(map.containsKey(Integer.valueOf(5)));

		assertFalse(map.remove("KEY", "other"));
		assertTrue(map.remove("KEY", "v"));
		assertFalse(map.containsKey("key"));

		assertEquals("computed", map.computeIfAbsent("New", key -> "computed"));
		assertEquals("computed", map.get("NEW"));
		assertEquals("computed!", map.computeIfPresent("NEW", (key, value) -> value + "!"));
		assertNull(map.computeIfPresent("Missing", (key, value) -> value + "!"));

		final Map<String, String> more = new LinkedHashMap<>();
		more.put("X-One", "1");
		more.put("x-ONE", "2");
		map.putAll(more);
		assertEquals("2", map.get("x-one"));
	}

	// ---------------------------------------------------------------- WindowsNetworkUtilities

	@Test
	public void testPrimaryDnsSuffixOnNonWindowsSystem() {
		final String originalOsName = System.getProperty("os.name");
		try {
			System.setProperty("os.name", "Linux");
			WindowsNetworkUtilities.clearPrimaryDnsSuffixCache();
			assertEquals("", WindowsNetworkUtilities.getPrimaryDnsSuffix());
			// cached value is returned on the second call
			assertEquals("", WindowsNetworkUtilities.getPrimaryDnsSuffix());
		} finally {
			System.setProperty("os.name", originalOsName);
			WindowsNetworkUtilities.clearPrimaryDnsSuffixCache();
		}
	}

	@Test
	public void testPrimaryDnsSuffixOnWindowsSystem() {
		final String originalOsName = System.getProperty("os.name");
		final java.io.PrintStream originalErr = System.err;
		try {
			System.setProperty("os.name", "Windows 11");
			// keep the "Could not determine" message of non-Windows test systems out of the test output
			System.setErr(new java.io.PrintStream(new java.io.ByteArrayOutputStream()));
			WindowsNetworkUtilities.clearPrimaryDnsSuffixCache();
			// On a real Windows system the registry is queried, elsewhere the "reg" command is missing.
			// Either way the result must not be null.
			assertNotNull(WindowsNetworkUtilities.getPrimaryDnsSuffix());
		} finally {
			System.setErr(originalErr);
			System.setProperty("os.name", originalOsName);
			WindowsNetworkUtilities.clearPrimaryDnsSuffixCache();
		}
	}

	@Test
	public void testRegistryOutputParsing() throws Exception {
		final Method parseRegistryValue = WindowsNetworkUtilities.class.getDeclaredMethod("parseRegistryValue", String.class, String.class);
		parseRegistryValue.setAccessible(true);

		final String registryOutput = "\r\nHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\r\n"
				+ "    Domain    REG_SZ    corp.example.com\r\n\r\n";
		assertEquals("corp.example.com", parseRegistryValue.invoke(null, registryOutput, "Domain"));
		assertNull(parseRegistryValue.invoke(null, "    Domain    REG_SZ    \r\n", "Domain"));
		assertNull(parseRegistryValue.invoke(null, "    Domain REG_SZ\r\n", "Domain"));
		assertNull(parseRegistryValue.invoke(null, "    Other    REG_SZ    x\r\n", "Domain"));
		assertNull(parseRegistryValue.invoke(null, null, "Domain"));

		final Method isNotBlank = WindowsNetworkUtilities.class.getDeclaredMethod("isNotBlank", String.class);
		isNotBlank.setAccessible(true);
		assertFalse((Boolean) isNotBlank.invoke(null, (Object) null));
		assertFalse((Boolean) isNotBlank.invoke(null, "  "));
		assertTrue((Boolean) isNotBlank.invoke(null, "x"));
	}
}
