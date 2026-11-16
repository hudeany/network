package de.soderer.network;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/**
 * Tests the variants of the OIDC login flow: identity provider selection, scripted and direct credential posts,
 * client-side redirects, GET forms, form field types, redirect handling and CSRF token sources.
 */
public class OidcLoginFlowTest {
	private static final String SESSION_ID = "c2Vzc2lvbg==";

	/** Handles a request; the request body is already read */
	private interface Route {
		void handle(HttpExchange exchange, String requestBody) throws IOException;
	}

	private HttpServer identityProvider;
	private HttpServer application;
	private String idp;
	private String app;
	private final Map<String, Route> idpRoutes = new ConcurrentHashMap<>();
	private final Map<String, Route> appRoutes = new ConcurrentHashMap<>();
	private final List<String> credentialRequests = new CopyOnWriteArrayList<>();

	@BeforeEach
	public void startServers() throws IOException {
		identityProvider = startServer(idpRoutes);
		application = startServer(appRoutes);
		idp = "http://127.0.0.1:" + identityProvider.getAddress().getPort();
		app = "http://localhost:" + application.getAddress().getPort();
	}

	@AfterEach
	public void stopServers() {
		identityProvider.stop(0);
		application.stop(0);
	}

	private static HttpServer startServer(final Map<String, Route> routes) throws IOException {
		final HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/", exchange -> {
			final String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
			final Route route = routes.get(exchange.getRequestURI().getPath());
			if (route == null) {
				respond(exchange, 404, "Not found");
			} else {
				route.handle(exchange, requestBody);
			}
		});
		server.start();
		return server;
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

	private static String html(final String body) {
		return "<html><body>" + body + "</body></html>";
	}

	private static String decoded(final String formData) {
		return URLDecoder.decode(formData == null ? "" : formData, StandardCharsets.UTF_8);
	}

	/**
	 * Standard application: "/" redirects to the given start of the identity provider without session, "/callback" sets
	 * the session cookie. The final page contains the given head content.
	 */
	private void standardApplication(final String identityProviderStartPath, final String pageHead) {
		appRoutes.put("/", (exchange, body) -> {
			final String cookies = exchange.getRequestHeaders().getFirst("Cookie");
			if (cookies != null && cookies.contains("SESSION=" + SESSION_ID)) {
				respond(exchange, 200, "<html><head><title>App</title>" + pageHead + "</head><body>Welcome</body></html>");
			} else {
				respond(exchange, 302, "", "Location", idp + identityProviderStartPath);
			}
		});
		appRoutes.put("/callback", (exchange, body) -> respond(exchange, 302, "", "Location", "/", "Set-Cookie", "SESSION=" + SESSION_ID + "; Path=/"));
	}

	/** Route of the identity provider that checks the credentials and redirects back to the application */
	private Route credentialCheck() {
		return (exchange, body) -> {
			final String data = decoded(body.isEmpty() ? exchange.getRequestURI().getRawQuery() : body);
			credentialRequests.add(data);
			if (data.contains("username=andreas") && data.contains("password=secret")) {
				respond(exchange, 302, "", "Location", app + "/callback?code=c1");
			} else {
				respond(exchange, 200, html("<p class='feedback'>" + "x".repeat(300) + "</p>"
						+ "<form method='post'><input name='username'><input type='password' name='password'></form>"));
			}
		};
	}

	private static String loginForm(final String action) {
		return "<form method='post' action='" + action + "'><input name='username'><input type='password' name='password'></form>";
	}

	private OidcLogin.LoginSession login(final String idpSelection) throws Exception {
		final OidcLogin oidcLogin = new OidcLogin(Duration.ofSeconds(10), idpSelection, "none", null);
		final OidcLogin.LoginSession session = oidcLogin.login(URI.create(app + "/"), "andreas", "secret");
		assertNotNull(session, oidcLogin.getLastFailureMessage());
		return session;
	}

	private String loginFailure(final String password) throws Exception {
		final OidcLogin oidcLogin = new OidcLogin(Duration.ofSeconds(10), null, "none", null);
		assertNull(oidcLogin.login(URI.create(app + "/"), "andreas", password));
		return oidcLogin.getLastFailureMessage();
	}

	@Test
	public void testIdentityProviderSelectionByProviderList() throws Exception {
		standardApplication("/auth", "");
		idpRoutes.put("/auth", (exchange, body) -> respond(exchange, 200, html("<script>var providers = ["
				+ "{\"displayName\":\"Other\",\"loginUrl\":\"\\/auth\\/other\"},"
				+ "{\"displayName\":\" Corp \",\"loginUrl\":\"\\/auth\\/corp?a=1\\u0026b=2\"}];</script>")));
		idpRoutes.put("/auth/corp", (exchange, body) -> {
			assertEquals("a=1&b=2", exchange.getRequestURI().getRawQuery());
			respond(exchange, 200, html(loginForm("/auth/login")));
		});
		idpRoutes.put("/auth/login", credentialCheck());
		assertNotNull(login("CORP"));
	}

	@Test
	public void testIdentityProviderSelectionByLink() throws Exception {
		standardApplication("/auth", "");
		idpRoutes.put("/auth", (exchange, body) -> respond(exchange, 200, html("<a href=\"/auth/other\">Other</a><a name='x'>Corp</a>"
				+ "<a class='idp' href=/auth/corp><span>Corp</span>&nbsp;</a>")));
		idpRoutes.put("/auth/corp", (exchange, body) -> respond(exchange, 200, html(loginForm("/auth/login"))));
		idpRoutes.put("/auth/login", credentialCheck());
		assertNotNull(login("corp"));
	}

	@Test
	public void testUnknownIdentityProviderSelectionIsIgnored() throws Exception {
		standardApplication("/auth", "");
		idpRoutes.put("/auth", (exchange, body) -> respond(exchange, 200, html(loginForm("/auth/login"))));
		idpRoutes.put("/auth/login", credentialCheck());
		assertNotNull(login("unknown"));
	}

	@Test
	public void testScriptedLoginAction() throws Exception {
		standardApplication("/auth", "");
		idpRoutes.put("/auth", (exchange, body) -> respond(exchange, 200,
				html("<div id='root'></div><script>window.kc = {\"loginAction\":\"" + idp.replace("/", "\\/") + "\\/auth\\/scripted?x=1\\u0026y=2\"};</script>")));
		idpRoutes.put("/auth/scripted", (exchange, body) -> {
			assertEquals("x=1&y=2", exchange.getRequestURI().getRawQuery());
			assertTrue(body.contains("credentialId="), body);
			credentialCheck().handle(exchange, body);
		});
		assertNotNull(login(null));
		assertEquals(1, credentialRequests.size());
	}

	@Test
	public void testDirectCredentialPost() throws Exception {
		standardApplication("/realms/test/login-actions/authenticate", "");
		idpRoutes.put("/realms/test/login-actions/authenticate", (exchange, body) -> {
			if ("GET".equals(exchange.getRequestMethod())) {
				respond(exchange, 200, html("<div id='kc-form-login'></div>"));
			} else {
				credentialCheck().handle(exchange, body);
			}
		});
		assertNotNull(login(null));
	}

	@Test
	public void testJavaScriptOnlyLoginIsNotSupported() throws Exception {
		standardApplication("/protocol/openid-connect/auth", "");
		idpRoutes.put("/protocol/openid-connect/auth", (exchange, body) -> respond(exchange, 200, html("<div id='app'>execution tab_id</div>")));
		final String failure = loginFailure("secret");
		assertTrue(failure.contains("No login form found"), failure);
	}

	@Test
	public void testNoLoginProcessingEndpoint() throws Exception {
		standardApplication("/welcome", "");
		idpRoutes.put("/welcome", (exchange, body) -> respond(exchange, 200, html("<p>Nothing to do here</p>")));
		final String failure = loginFailure("secret");
		assertTrue(failure.contains("still at identity provider"), failure);
	}

	@Test
	public void testClientSideRedirects() throws Exception {
		standardApplication("/auth/meta", "");
		idpRoutes.put("/auth/meta", (exchange, body) -> respond(exchange, 200,
				"<html><head><meta http-equiv=\"refresh\" content=\"0; url=/auth/script\"></head></html>"));
		idpRoutes.put("/auth/script", (exchange, body) -> respond(exchange, 200, html("<script>window.location.href = '/auth/form';</script>")));
		idpRoutes.put("/auth/form", (exchange, body) -> respond(exchange, 200, html(loginForm("/auth/login"))));
		idpRoutes.put("/auth/login", credentialCheck());
		assertNotNull(login(null));
	}

	@Test
	public void testGetFormAndFieldTypes() throws Exception {
		standardApplication("/auth", "");
		idpRoutes.put("/auth", (exchange, body) -> respond(exchange, 200, html("<form action='/auth/getlogin?old=1#top'>"
				+ "<input type=\"hidden\" name=\"entities\" value=\"a&amp;b&#x41;&#66;&quot;&lt;&gt;&apos;&nbsp;&unknown;\">"
				+ "<input type='checkbox' name='remember' checked><input type='checkbox' name='unchecked' value='x'>"
				+ "<input type='radio' name='choice' value='two' checked><input type='radio' name='choice' value='one'>"
				+ "<select name='language'><option>de</option></select><textarea name='note'></textarea>"
				+ "<input type='reset' name='reset'><input type='file' name='upload'><input name='disabled' disabled><input value='noName'>"
				+ "<input type=email name='mail'><input type='password' name='password'>"
				+ "<button name='button' type='button'>Help</button><input type='image' name='first' value='1'><button name='second'>Login</button>"
				+ "</form>")));
		idpRoutes.put("/auth/getlogin", (exchange, body) -> {
			final String query = decoded(exchange.getRequestURI().getRawQuery());
			assertTrue(query.startsWith("entities=a&bAB\"<>' &unknown;&remember=on&choice=two&note=&mail=andreas&password=secret&first=1"), query);
			assertTrue(!query.contains("old=1") && !query.contains("unchecked") && !query.contains("disabled") && !query.contains("second"), query);
			respond(exchange, 302, "", "Location", app + "/callback?code=c1");
		});
		assertNotNull(login(null));
	}

	@Test
	public void testTwoStepLoginWithEmailField() throws Exception {
		standardApplication("/auth", "");
		idpRoutes.put("/auth", (exchange, body) -> respond(exchange, 200,
				html("<form method='post' action='/auth/step2'><input type='email' name='identifier'><input type='submit' value='Next'></form>")));
		idpRoutes.put("/auth/step2", (exchange, body) -> {
			assertTrue(decoded(body).contains("identifier=andreas"), body);
			respond(exchange, 200, html("<form method='post' action='/auth/login'><input type='hidden' name='username' value='andreas'>"
					+ "<input type='password' name='password'></form>"));
		});
		idpRoutes.put("/auth/login", credentialCheck());
		assertNotNull(login(null));
	}

	@Test
	public void testAutoPostFormWithoutScript() throws Exception {
		standardApplication("/auth", "");
		idpRoutes.put("/auth", (exchange, body) -> respond(exchange, 200, html(loginForm("/auth/login"))));
		idpRoutes.put("/auth/login", (exchange, body) -> respond(exchange, 200,
				html("<form method='post' action='" + app + "/callback'><input type='hidden' name='state' value='s'><input type='submit' name='go' value='Go'></form>")));
		assertNotNull(login(null));
	}

	@Test
	public void testTemporaryRedirectKeepsPostBody() throws Exception {
		standardApplication("/auth", "");
		idpRoutes.put("/auth", (exchange, body) -> respond(exchange, 200, html(loginForm("/auth/login"))));
		idpRoutes.put("/auth/login", (exchange, body) -> respond(exchange, 307, "", "Location", "/auth/login2"));
		idpRoutes.put("/auth/login2", (exchange, body) -> {
			assertEquals("POST", exchange.getRequestMethod());
			credentialCheck().handle(exchange, body);
		});
		assertNotNull(login(null));
	}

	@Test
	public void testWrongPasswordWithLongErrorText() throws Exception {
		standardApplication("/auth", "");
		idpRoutes.put("/auth", (exchange, body) -> respond(exchange, 200, html(loginForm("/auth/login"))));
		idpRoutes.put("/auth/login", credentialCheck());
		final String failure = loginFailure("wrong");
		assertTrue(failure.contains("x".repeat(200) + "..."), failure);
	}

	@Test
	public void testWrongPasswordWithoutErrorText() throws Exception {
		standardApplication("/auth", "");
		idpRoutes.put("/auth", (exchange, body) -> respond(exchange, 200, html(loginForm("/auth/login"))));
		idpRoutes.put("/auth/login", (exchange, body) -> respond(exchange, 200, html("<div class='error'> </div>" + loginForm("/auth/login"))));
		final String failure = loginFailure("wrong");
		assertTrue(failure.startsWith("Login form was shown again after submitting the credentials (wrong username/password?) (final URL"), failure);
	}

	@Test
	public void testErrorStatusOfStartPage() throws Exception {
		appRoutes.put("/", (exchange, body) -> respond(exchange, 500, "Internal error"));
		assertTrue(loginFailure("secret").startsWith("Final page returned HTTP 500"));
	}

	@Test
	public void testRedirectWithoutLocationIsFinalPage() throws Exception {
		appRoutes.put("/", (exchange, body) -> respond(exchange, 302, ""));
		assertTrue(loginFailure("secret").startsWith("Final page returned HTTP 302"));
	}

	@Test
	public void testUnprotectedPageWithPasswordFormAfterLogin() throws Exception {
		appRoutes.put("/", (exchange, body) -> respond(exchange, 200, html("<form><input type='password' name='pin'></form>")));
		assertTrue(loginFailure("secret").startsWith("Login form was shown again"));
	}

	@Test
	public void testUnprotectedPage() throws Exception {
		appRoutes.put("/", (exchange, body) -> respond(exchange, 200, html("Public")));
		assertNotNull(login(null));
	}

	@Test
	public void testRedirectToUnsupportedScheme() {
		appRoutes.put("/", (exchange, body) -> respond(exchange, 302, "", "Location", "ftp://example.com/file"));
		final Exception exception = assertThrows(IllegalStateException.class, () -> loginFailure("secret"));
		assertTrue(exception.getMessage().contains("unsupported URL scheme"));
	}

	@Test
	public void testTooManyRedirects() {
		appRoutes.put("/", (exchange, body) -> respond(exchange, 302, "", "Location", "/"));
		final Exception exception = assertThrows(IllegalStateException.class, () -> loginFailure("secret"));
		assertTrue(exception.getMessage().contains("Too many redirects"));
	}

	@Test
	public void testCsrfTokenFromJavaScriptVariable() throws Exception {
		standardApplication("/auth", "<script>window.csrfToken = 'js-token';</script>");
		idpRoutes.put("/auth", (exchange, body) -> respond(exchange, 200, html(loginForm("/auth/login"))));
		idpRoutes.put("/auth/login", credentialCheck());
		assertEquals("js-token", login(null).getCsrfToken());
	}

	@Test
	public void testCsrfTokenFromJsonProperty() throws Exception {
		standardApplication("/auth", "<script>var config = {\"_csrf\": \"json\\/token\"};</script>");
		idpRoutes.put("/auth", (exchange, body) -> respond(exchange, 200, html(loginForm("/auth/login"))));
		idpRoutes.put("/auth/login", credentialCheck());
		assertEquals("json/token", login(null).getCsrfToken());
	}

	@Test
	public void testCsrfTokenFromCookie() throws Exception {
		standardApplication("/auth", "");
		appRoutes.put("/callback", (exchange, body) -> respond(exchange, 302, "", "Location", "/", "Set-Cookie", "SESSION=" + SESSION_ID + "; Path=/",
				"Set-Cookie", "EMPTY_XSRF=; Path=/", "Set-Cookie", "XSRF-TOKEN=cookie-token; Path=/"));
		idpRoutes.put("/auth", (exchange, body) -> respond(exchange, 200, html(loginForm("/auth/login"))));
		idpRoutes.put("/auth/login", credentialCheck());
		assertEquals("cookie-token", login(null).getCsrfToken());
	}

	@Test
	public void testCsrfTokenFetchResponses() throws Exception {
		standardApplication("/auth", "");
		idpRoutes.put("/auth", (exchange, body) -> respond(exchange, 200, html(loginForm("/auth/login"))));
		idpRoutes.put("/auth/login", credentialCheck());
		appRoutes.put("/required", (exchange, body) -> respond(exchange, 403, "", "X-CSRF-TOKEN", "Required", "X-Other", "x"));
		appRoutes.put("/several", (exchange, body) -> respond(exchange, 200, "", "X-XSRF-TOKEN", "Fetch", "X-XSRF-TOKEN", "header-token"));
		appRoutes.put("/body", (exchange, body) -> respond(exchange, 200, "<meta name='csrf' content='body&amp;token'>"));
		final OidcLogin.LoginSession session = login(null);
		assertNull(session.fetchCsrfToken(null));
		assertNull(session.fetchCsrfToken(URI.create(app + "/required")));
		assertEquals("header-token", session.fetchCsrfToken(URI.create(app + "/several")));
		assertEquals("body&token", session.fetchCsrfToken(URI.create(app + "/body")));
		assertEquals("body&token", session.getCsrfToken());
		assertNull(session.fetchCsrfToken(URI.create("http://127.0.0.1:1/unreachable")));
		assertTrue(session.toString().startsWith("LoginSession @ " + app));
	}

	@Test
	public void testNoCsrfTokenAtAll() throws Exception {
		standardApplication("/auth", "");
		idpRoutes.put("/auth", (exchange, body) -> respond(exchange, 200, html(loginForm("/auth/login"))));
		idpRoutes.put("/auth/login", credentialCheck());
		final OidcLogin.LoginSession session = login(null);
		assertNull(session.getCsrfToken());
		// Determined only once
		assertNull(session.getCsrfToken());
		assertEquals(404, session.send("GET", URI.create(app + "/missing"), null, null).statusCode());
	}
}
