package de.soderer.network;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/**
 * Tests the OIDC login flow with a local web application and a local identity provider on different origins.
 */
@SuppressWarnings("static-method")
public class OidcLoginTest {
	/** Base64 value with "=" padding, which must be sent unchanged */
	private static final String SESSION_ID = "YWJjZGVmZ2hpams==";

	private HttpServer identityProvider;
	private HttpServer application;
	private String identityProviderBaseUrl;
	private String applicationBaseUrl;

	/** Configurable behaviour of the identity provider */
	private volatile boolean twoStepLogin;
	private volatile boolean formPostResponse;
	/** Configurable behaviour of the application */
	private volatile boolean csrfTokenInPage = true;
	private volatile boolean csrfTokenOnlyByFetch;

	private final List<String> userAgents = new CopyOnWriteArrayList<>();
	private final List<String> applicationCookieHeaders = new CopyOnWriteArrayList<>();

	@BeforeEach
	public void startServers() throws IOException {
		identityProvider = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		application = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		identityProviderBaseUrl = "http://127.0.0.1:" + identityProvider.getAddress().getPort();
		// Other host name than the identity provider: other origin and other cookie domain
		applicationBaseUrl = "http://localhost:" + application.getAddress().getPort();

		identityProvider.createContext("/auth", this::handleIdentityProvider);
		application.createContext("/", this::handleApplication);
		identityProvider.start();
		application.start();
	}

	@AfterEach
	public void stopServers() {
		identityProvider.stop(0);
		application.stop(0);
	}

	private void handleIdentityProvider(final HttpExchange exchange) throws IOException {
		userAgents.add(exchange.getRequestHeaders().getFirst("User-Agent"));
		final String path = exchange.getRequestURI().getPath();
		final String cookies = cookieHeader(exchange);
		if ("GET".equals(exchange.getRequestMethod())) {
			final String form = twoStepLogin
					? "<form method='post' action='/auth/username'><input name='username'><button type='submit'>Next</button></form>"
					: "<form method='post' action='/auth/login'><input name='username'><input type='password' name='password'><button type='submit' name='login' value='x'>Login</button></form>";
			respond(exchange, 200, "<html><body>" + form + "</body></html>",
					"Set-Cookie", "KC_RESTART=r1==; Path=/", "Set-Cookie", "AUTH_SESSION=s2; Path=/auth");
			return;
		}

		final String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
		if (exchange.getRequestHeaders().getFirst("Origin") == null) {
			respond(exchange, 403, "Origin header missing");
		} else if (!cookies.contains("KC_RESTART=r1==") || !cookies.contains("AUTH_SESSION=s2")) {
			respond(exchange, 400, "Cookies of the identity provider missing: " + cookies);
		} else if ("/auth/username".equals(path)) {
			respond(exchange, 200, "<form method='post' action='/auth/login'><input type='hidden' name='username' value='andreas'><input type='password' name='password'></form>");
		} else if (!body.contains("username=andreas") || !body.contains("password=geh%26eim")) {
			respond(exchange, 200, "<div class='alert-error'>Invalid username or password.</div>"
					+ "<form method='post' action='/auth/login'><input name='username'><input type='password' name='password'></form>");
		} else if (formPostResponse) {
			respond(exchange, 200, "<html><body onload='document.forms[0].submit()'><form method='post' action='" + applicationBaseUrl + "/callback'>"
					+ "<input type='hidden' name='code' value='abc123'><input type='hidden' name='state' value='1'></form></body></html>");
		} else {
			respond(exchange, 302, "", "Location", applicationBaseUrl + "/callback?state=1&code=abc123");
		}
	}

	private void handleApplication(final HttpExchange exchange) throws IOException {
		userAgents.add(exchange.getRequestHeaders().getFirst("User-Agent"));
		final String path = exchange.getRequestURI().getPath();
		final String cookies = cookieHeader(exchange);
		applicationCookieHeaders.add(cookies);
		final boolean loggedIn = cookies.contains("SESSION=" + SESSION_ID);
		if ("/callback".equals(path)) {
			final String query = exchange.getRequestURI().getQuery();
			final String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
			if ((query == null || !query.contains("code=abc123")) && !body.contains("code=abc123")) {
				respond(exchange, 400, "Missing code");
			} else {
				respond(exchange, 302, "", "Location", "/", "Set-Cookie", "SESSION=" + SESSION_ID + "; Path=/; HttpOnly");
			}
		} else if ("/api/version".equals(path)) {
			final String csrfToken = exchange.getRequestHeaders().getFirst("X-CSRF-TOKEN");
			if (!loggedIn) {
				respond(exchange, 401, "No session");
			} else if ("Fetch".equals(csrfToken)) {
				respond(exchange, 200, "", "X-CSRF-TOKEN", "fetched-token");
			} else if (!(csrfTokenOnlyByFetch ? "fetched-token" : "meta-token").equals(csrfToken)) {
				respond(exchange, 403, "Invalid CSRF token", "X-CSRF-TOKEN", "Required");
			} else {
				final String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
				respond(exchange, 200, "{\"method\":\"" + exchange.getRequestMethod() + "\",\"body\":" + (body.isEmpty() ? "null" : body)
						+ ",\"contentType\":\"" + exchange.getRequestHeaders().getFirst("Content-Type") + "\"}");
			}
		} else if (loggedIn) {
			if ("Fetch".equals(exchange.getRequestHeaders().getFirst("X-CSRF-TOKEN"))) {
				respond(exchange, 200, "", "X-CSRF-TOKEN", "fetched-token");
			} else {
				respond(exchange, 200, "<html><head><title>App</title>" + (csrfTokenInPage ? "<meta name=\"_csrf\" content=\"meta-token\">" : "")
						+ "</head><body>Welcome</body></html>", "Content-Type", "text/html; charset=UTF-8");
			}
		} else {
			respond(exchange, 302, "", "Location", identityProviderBaseUrl + "/auth?client_id=app");
		}
	}

	private static String cookieHeader(final HttpExchange exchange) {
		final String cookies = exchange.getRequestHeaders().getFirst("Cookie");
		return cookies == null ? "" : cookies;
	}

	private static void respond(final HttpExchange exchange, final int status, final String body, final String... headers) throws IOException {
		for (int i = 0; i < headers.length; i += 2) {
			exchange.getResponseHeaders().add(headers[i], headers[i + 1]);
		}
		final byte[] data = body.getBytes(StandardCharsets.UTF_8);
		exchange.sendResponseHeaders(status, data.length == 0 ? -1 : data.length);
		if (data.length > 0) {
			exchange.getResponseBody().write(data);
		}
		exchange.close();
	}

	private OidcLogin.LoginSession login(final String password) throws Exception {
		final OidcLogin oidcLogin = new OidcLogin(Duration.ofSeconds(10), null, "none", null);
		final OidcLogin.LoginSession session = oidcLogin.login(URI.create(applicationBaseUrl + "/"), "andreas", password);
		if (session == null) {
			throw new AssertionError("Login failed: " + oidcLogin.getLastFailureMessage());
		}
		return session;
	}

	@Test
	public void testLoginAndSessionRequest() throws Exception {
		final OidcLogin.LoginSession session = login("geh&eim");
		assertTrue(session.getFinalPageUri().toString().startsWith(applicationBaseUrl));
		assertEquals("meta-token", session.getCsrfToken());

		final OidcLogin.LoginSession.SessionResponse response = session.send("POST", URI.create(applicationBaseUrl + "/api/version"),
				Map.of("X-CSRF-TOKEN", session.getCsrfToken(), "Content-Type", "application/json"), "{\"a\":1}");
		assertEquals(200, response.statusCode());
		assertEquals("{\"method\":\"POST\",\"body\":{\"a\":1},\"contentType\":\"application/json\"}", response.body());

		// Cookies of the identity provider never reach the application, the session cookie is sent unchanged
		for (final String cookies : applicationCookieHeaders) {
			assertFalse(cookies.contains("KC_RESTART") || cookies.contains("AUTH_SESSION"), cookies);
		}
		assertTrue(applicationCookieHeaders.get(applicationCookieHeaders.size() - 1).contains("SESSION=" + SESSION_ID));
	}

	@Test
	public void testWrongPassword() throws Exception {
		final OidcLogin oidcLogin = new OidcLogin(Duration.ofSeconds(10), null, "none", null);
		assertNull(oidcLogin.login(URI.create(applicationBaseUrl + "/"), "andreas", "wrong"));
		assertTrue(oidcLogin.getLastFailureMessage().contains("wrong username/password"), oidcLogin.getLastFailureMessage());
		assertTrue(oidcLogin.getLastFailureMessage().contains("Invalid username or password."), oidcLogin.getLastFailureMessage());
	}

	@Test
	public void testTwoStepLoginWithFormPostResponse() throws Exception {
		twoStepLogin = true;
		formPostResponse = true;
		assertEquals("meta-token", login("geh&eim").getCsrfToken());
	}

	@Test
	public void testCsrfTokenByFetchRequest() throws Exception {
		csrfTokenInPage = false;
		csrfTokenOnlyByFetch = true;
		final OidcLogin.LoginSession session = login("geh&eim");
		assertEquals("fetched-token", session.getCsrfToken());
		assertEquals(200, session.send("GET", URI.create(applicationBaseUrl + "/api/version"), Map.of("X-CSRF-TOKEN", session.getCsrfToken()), null).statusCode());
	}

	@Test
	public void testRejectedCsrfTokenIsRenewed() throws Exception {
		final OidcLogin.LoginSession session = login("geh&eim");
		csrfTokenOnlyByFetch = true;
		final URI apiUri = URI.create(applicationBaseUrl + "/api/version");
		assertEquals(403, session.send("GET", apiUri, Map.of("X-CSRF-TOKEN", session.getCsrfToken()), null).statusCode());
		assertEquals("fetched-token", session.fetchCsrfToken(apiUri));
		assertEquals("fetched-token", session.getCsrfToken());
		assertEquals(200, session.send("GET", apiUri, Map.of("X-CSRF-TOKEN", session.getCsrfToken()), null).statusCode());
	}

	@Test
	public void testUserAgent() throws Exception {
		final OidcLogin oidcLogin = new OidcLogin(Duration.ofSeconds(10), null, "none", null).withUserAgent("TestAgent/1.0");
		assertNotNull(oidcLogin.login(URI.create(applicationBaseUrl + "/"), "andreas", "geh&eim"));
		assertFalse(userAgents.isEmpty());
		for (final String userAgent : userAgents) {
			assertEquals("TestAgent/1.0", userAgent);
		}
		oidcLogin.setUserAgent(null);
		assertEquals(OidcLogin.DEFAULT_USER_AGENT, oidcLogin.getUserAgent());
	}

	@Test
	public void testInvalidProxyUrl() {
		assertThrows(IllegalArgumentException.class, () -> new OidcLogin(Duration.ofSeconds(10), null, "socks://proxy:1080", null));
		assertThrows(IllegalArgumentException.class, () -> new OidcLogin(Duration.ofSeconds(10), null, "proxy", null));
	}
}
