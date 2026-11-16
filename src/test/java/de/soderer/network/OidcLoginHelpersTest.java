package de.soderer.network;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.net.URI;

import org.junit.jupiter.api.Test;

/**
 * Tests the private helper functions of {@link OidcLogin} for edge cases, which are hard to reach by a complete
 * login flow.
 */
@SuppressWarnings("static-method")
public class OidcLoginHelpersTest {
	private static Object invoke(final String name, final Class<?>[] types, final Object... arguments) throws Exception {
		final Method method = OidcLogin.class.getDeclaredMethod(name, types);
		method.setAccessible(true);
		return method.invoke(null, arguments);
	}

	@Test
	public void testDecodeEntities() throws Exception {
		final Class<?>[] types = { String.class };
		assertNull(invoke("decodeEntities", types, (Object) null));
		assertEquals("plain", invoke("decodeEntities", types, "plain"));
		assertEquals("& <>\"' AB -x", invoke("decodeEntities", types, "&amp;&nbsp;&lt;&gt;&quot;&apos;&#32;&#x41;&#X42; -x").toString().replace("  ", " "));
		assertEquals("&unknown; &", invoke("decodeEntities", types, "&unknown; &"));
	}

	@Test
	public void testUnescapeJsString() throws Exception {
		final Class<?>[] types = { String.class };
		assertNull(invoke("unescapeJsString", types, (Object) null));
		assertEquals("a/b&c\\d", invoke("unescapeJsString", types, "a\\/b\\u0026c\\\\d"));
	}

	@Test
	public void testResolveHttpUri() throws Exception {
		final Class<?>[] types = { URI.class, String.class };
		final URI base = URI.create("https://host/path/page");
		assertNull(invoke("resolveHttpUri", types, base, null));
		assertNull(invoke("resolveHttpUri", types, base, " "));
		assertNull(invoke("resolveHttpUri", types, base, "javascript:void(0)"));
		assertNull(invoke("resolveHttpUri", types, base, "http://in valid\\path"));
		assertEquals(URI.create("https://host/path/a%20b"), invoke("resolveHttpUri", types, base, " a b "));
		assertEquals(URI.create("http://other/x"), invoke("resolveHttpUri", types, base, "http://other/x"));
	}

	@Test
	public void testSameOriginAndPorts() throws Exception {
		final Class<?>[] types = { URI.class, URI.class };
		assertTrue((Boolean) invoke("isSameOrigin", types, URI.create("https://Host/a"), URI.create("https://host:443/b")));
		assertTrue((Boolean) invoke("isSameOrigin", types, URI.create("http://host/a"), URI.create("http://host:80/b")));
		assertFalse((Boolean) invoke("isSameOrigin", types, URI.create("http://host/a"), URI.create("https://host/a")));
		assertFalse((Boolean) invoke("isSameOrigin", types, URI.create("http://host/a"), URI.create("http://other/a")));
		assertFalse((Boolean) invoke("isSameOrigin", types, URI.create("http://host:8080/a"), URI.create("http://host/a")));
	}

	@Test
	public void testDirectCredentialPostTarget() throws Exception {
		final Class<?>[] types = { URI.class, String.class };
		assertFalse((Boolean) invoke("isLikelyDirectCredentialPostTarget", types, URI.create("https://idp/realms/x/protocol/openid-connect/auth"), "kc-form-login"));
		assertFalse((Boolean) invoke("isLikelyDirectCredentialPostTarget", types, URI.create("https://idp/oauth2/authorize"), null));
		assertFalse((Boolean) invoke("isLikelyDirectCredentialPostTarget", types, URI.create("https://idp/connect/authorize"), null));
		assertTrue((Boolean) invoke("isLikelyDirectCredentialPostTarget", types, URI.create("https://idp/login"), null));
		assertTrue((Boolean) invoke("isLikelyDirectCredentialPostTarget", types, URI.create("https://idp/authenticate"), null));
		assertTrue((Boolean) invoke("isLikelyDirectCredentialPostTarget", types, URI.create("https://idp/x"), "SESSION_CODE"));
		assertTrue((Boolean) invoke("isLikelyDirectCredentialPostTarget", types, URI.create("https://idp/x"), "execution"));
		assertTrue((Boolean) invoke("isLikelyDirectCredentialPostTarget", types, URI.create("https://idp/x"), "tab_id"));
		assertFalse((Boolean) invoke("isLikelyDirectCredentialPostTarget", types, URI.create("https://idp/x"), null));
		assertFalse((Boolean) invoke("isLikelyDirectCredentialPostTarget", types, URI.create("urn:isbn:123"), "nothing"));
	}

	@Test
	public void testExtractErrorText() throws Exception {
		final Class<?>[] types = { String.class };
		assertNull(invoke("extractErrorText", types, "<p>no error</p>"));
		assertEquals("Invalid user.", invoke("extractErrorText", types, "<span id='input-error'> <b>Invalid</b> user. </span>"));
	}
}
