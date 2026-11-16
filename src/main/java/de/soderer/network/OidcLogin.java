package de.soderer.network;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.TrustManager;

/**
 * Login to web applications protected by an OIDC login (authorization code flow).
 * <p>
 * Behaves like a simple browser without JavaScript: follows redirects, keeps cookies,
 * fills and submits the login form of the identity provider (username/password, also
 * two-step forms), submits auto-post forms (response_mode=form_post) and finally checks
 * whether the main page of the web application is delivered successfully.
 * </p>
 * <p>
 * The login forms are detected heuristically (best effort, tested with Keycloak style
 * identity providers). Logins that need JavaScript are not supported.
 * </p>
 * <p>
 * A successful {@link #login(URI, String, String)} returns a {@link LoginSession} for further requests with the
 * cookies of the logged in session: {@link LoginSession#send(String, URI, Map, String)} sends them, and
 * {@link LoginSession#getCsrfToken()} delivers the CSRF token (header "X-CSRF-TOKEN").
 * </p>
 *
 * <pre>
 * final OidcLogin oidcLogin = new OidcLogin(Duration.ofSeconds(30), null, null, null);
 * final OidcLogin.LoginSession session = oidcLogin.login(URI.create("https://app.example.com/"), "user", "password");
 * if (session == null) {
 * 	throw new Exception(oidcLogin.getLastFailureMessage());
 * }
 * final Map&lt;String, String&gt; headers = Map.of("X-CSRF-TOKEN", session.getCsrfToken());
 * final OidcLogin.LoginSession.SessionResponse response = session.send("GET", URI.create("https://app.example.com/api/version"), headers, null);
 * </pre>
 */
public class OidcLogin {
	/**
	 * Default value of the header "User-Agent": a browser-like value, because some identity providers reject unknown
	 * clients.
	 */
	public static final String DEFAULT_USER_AGENT = "Mozilla/5.0 (OidcLogin) Gecko/20100101 Firefox/130.0";

	private static final int MAX_REDIRECTS = 25;
	private static final int MAX_FORM_SUBMITS = 10;
	private static final Pattern USERNAME_FIELD_PATTERN = Pattern.compile("(?i).*(user|login|email|mail|identifier|account|uid).*");
	private static final Pattern META_REFRESH_URL_PATTERN = Pattern.compile("(?is)<meta\\b[^>]*http-equiv\\s*=\\s*[\"']?refresh[\"']?[^>]*content\\s*=\\s*[\"'][^\"']*url\\s*=\\s*([^\"'>;\\s]+)[\"']");
	private static final Pattern JS_LOCATION_PATTERN = Pattern.compile("(?is)(?:window\\.)?location(?:\\.href)?\\s*=\\s*['\"]([^'\"]+)['\"]");
	private static final Pattern LOGIN_ACTION_PATTERN = Pattern.compile("(?is)\"loginAction\"\\s*:\\s*\"([^\"]+)\"");
	private static final Pattern PROVIDER_PAIR_PATTERN = Pattern.compile("(?is)\"displayName\"\\s*:\\s*\"([^\"]+)\".{0,1500}?\"loginUrl\"\\s*:\\s*\"([^\"]+)\"");
	private static final Pattern ANCHOR_PATTERN = Pattern.compile("(?is)<a\\b([^>]*)>(.*?)</a>");
	private static final Pattern HREF_ATTR_PATTERN = Pattern.compile("(?is)\\bhref\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s\"'>]+))");
	private static final Pattern CSRF_META_PATTERN = Pattern.compile("(?is)<meta\\b[^>]*name\\s*=\\s*[\"'](?:_csrf_token|_csrf|csrf|xsrf-token|xsrf_token|x-csrf-token|x_csrf_token)[\"'][^>]*content\\s*=\\s*[\"']([^\"']+)[\"']");
	private static final Pattern AUTO_SUBMIT_SCRIPT_PATTERN = Pattern.compile("(?i)\\.submit\\s*\\(");
	private static final Pattern ERROR_TEXT_PATTERN = Pattern.compile("(?is)<(span|div|p)\\b[^>]*(?:id|class)\\s*=\\s*[\"'][^\"']*(?:error|alert|feedback)[^\"']*[\"'][^>]*>(.*?)</\\1>");
	private static final Pattern HTML_TAG_PATTERN = Pattern.compile("(?s)<[^>]*>");
	private static final Pattern WHITESPACE_PATTERN = Pattern.compile("\\s+");
	private static final Pattern HTML_ENTITY_PATTERN = Pattern.compile("&(#[xX][0-9a-fA-F]+|#[0-9]+|amp|lt|gt|quot|apos|nbsp);");
	private static final Pattern CSRF_JS_PATTERN = Pattern.compile("(?is)(?:\"(?:csrfToken|_csrf_token|_csrf|csrf|X-CSRF-TOKEN|X_CSRF_TOKEN)\"\\s*:\\s*\"([^\"]+)\"|(?:csrfToken|_csrf_token|_csrf|csrf|X-CSRF-TOKEN|X_CSRF_TOKEN)\\s*=\\s*[\"']([^\"']+)[\"'])");

	private final Duration requestTimeout;
	private final String idpSelectionText;

	/** Request settings; each login gets its own {@link HttpTransport} with its own cookies */
	private final String proxyUrl;
	/** Trust manager for the TLS server certificates, null for the trust store of the JVM (cacerts) */
	private final TrustManager trustManager;
	private String userAgent = DEFAULT_USER_AGENT;

	/** Transport (cookies, proxy, TLS trust) of the currently running login */
	private HttpTransport transport;
	/** Reason of the failure of the last login, null if it succeeded */
	private String lastFailureMessage;

	/**
	 * Creates a login client.
	 *
	 * @param timeout
	 *            connect and read timeout per request
	 * @param idpSelectionText
	 *            text of the button or link of the identity provider to select before the login (federated login), null
	 *            if there is no selection
	 * @param proxyUrl
	 *            "http://host:port" or "host:port" for an HTTP proxy, "none"/"direct" for a direct connection, null or
	 *            blank for the system proxy settings
	 * @param trustManager
	 *            trust manager for the TLS server certificates (e.g. of a configured keystore); null for the default
	 *            trust store of the JVM (cacerts). The hostname verification stays active.
	 * @throws IllegalArgumentException
	 *             if the proxy URL is invalid
	 */
	public OidcLogin(final Duration timeout, final String idpSelectionText, final String proxyUrl, final TrustManager trustManager) {
		// Validated here, so an invalid proxy URL fails before the first request
		HttpUtilities.validateProxyUrl(proxyUrl);
		requestTimeout = timeout;
		this.idpSelectionText = idpSelectionText;
		this.proxyUrl = proxyUrl;
		this.trustManager = trustManager;
	}

	/**
	 * Returns the value of the header "User-Agent" of all requests.
	 *
	 * @return the user agent
	 */
	public String getUserAgent() {
		return userAgent;
	}

	/**
	 * Sets the value of the header "User-Agent" of all requests of further logins and their sessions.
	 *
	 * @param userAgent
	 *            the user agent, null for {@link #DEFAULT_USER_AGENT}
	 */
	public void setUserAgent(final String userAgent) {
		this.userAgent = userAgent == null ? DEFAULT_USER_AGENT : userAgent;
	}

	/**
	 * Sets the value of the header "User-Agent", see {@link #setUserAgent(String)}.
	 *
	 * @param newUserAgent
	 *            the user agent, null for {@link #DEFAULT_USER_AGENT}
	 * @return this login for chaining
	 */
	public OidcLogin withUserAgent(final String newUserAgent) {
		setUserAgent(newUserAgent);
		return this;
	}

	/**
	 * Executes the complete login flow and checks the resulting page: it must be delivered successfully by the web
	 * application itself and must not contain a password form.
	 *
	 * @param startUri
	 *            URI of the web application, which redirects to the identity provider
	 * @param user
	 *            the username at the identity provider
	 * @param password
	 *            the password
	 * @return the logged in session (CSRF token, cookies) if the web application main page was delivered
	 *         successfully after login, otherwise null (see {@link #getLastFailureMessage()})
	 * @throws Exception
	 *             if a request fails (connection, TLS, too many redirects)
	 */
	public LoginSession login(final URI startUri, final String user, final String password) throws Exception {
		lastFailureMessage = null;
		// Each login gets its own cookie store, a new login must not reuse the session of a previous login
		transport = new HttpTransport(proxyUrl, trustManager, requestTimeout, userAgent);

		Page page = send("GET", startUri, null, null);
		boolean loginPageSeen = false;
		boolean usernameSubmitted = false;
		boolean passwordSubmitted = false;
		boolean directCredentialPostAttempted = false;
		boolean idpSelectionDone = false;

		for (int submitCount = 0; submitCount < MAX_FORM_SUBMITS; submitCount++) {
			if (page.status >= 400) {
				break;
			}

			final List<HtmlForm> forms = HtmlForm.parseAll(page.body, page.uri);

			if (!idpSelectionDone && idpSelectionText != null && !idpSelectionText.isBlank()) {
				final URI providerTarget = findIdpSelectionTarget(page, idpSelectionText);
				if (providerTarget != null && !providerTarget.equals(page.uri)) {
					page = send("GET", providerTarget, null, page.uri);
					loginPageSeen = true;
					idpSelectionDone = true;
					continue;
				}
			}

			final HtmlForm passwordForm = findPasswordForm(forms);
			if (passwordForm != null) {
				loginPageSeen = true;
				if (passwordSubmitted) {
					final String errorText = extractErrorText(page.body);
					return fail("Login form was shown again after submitting the credentials (wrong username/password?)"
							+ (errorText != null ? ": " + errorText : ""), page);
				}
				final String passwordFieldName = passwordForm.getFirstFieldNameOfType("password");
				final String usernameFieldName = findUsernameFieldName(passwordForm);
				final Map<String, String> values = passwordForm.getDefaultValues();
				if (usernameFieldName != null) {
					values.put(usernameFieldName, user);
				}
				values.put(passwordFieldName, password);
				page = submit(passwordForm, values, page.uri);
				passwordSubmitted = true;
				continue;
			}

			final HtmlForm autoPostForm = findAutoPostForm(forms, page.body);
			if (autoPostForm != null) {
				page = submit(autoPostForm, autoPostForm.getDefaultValues(), page.uri);
				continue;
			}

			final URI clientSideRedirect = findClientSideRedirect(page);
			if (clientSideRedirect != null && !clientSideRedirect.equals(page.uri)) {
				page = send("GET", clientSideRedirect, null, page.uri);
				continue;
			}

			if (!usernameSubmitted && !passwordSubmitted && !isSameOrigin(page.uri, startUri)) {
				final HtmlForm usernameForm = findUsernameOnlyForm(forms);
				if (usernameForm != null) {
					// First step of a two-step login (username first, password on the next page)
					loginPageSeen = true;
					final Map<String, String> values = usernameForm.getDefaultValues();
					values.put(findUsernameFieldName(usernameForm), user);
					page = submit(usernameForm, values, page.uri);
					usernameSubmitted = true;
					continue;
				}
			}

			if (!directCredentialPostAttempted && !isSameOrigin(page.uri, startUri) && !hasAnyFormField(forms)) {
				final URI scriptedLoginAction = findScriptedLoginAction(page);
				if (scriptedLoginAction != null) {
					final Map<String, String> values = new LinkedHashMap<>();
					values.put("username", user);
					values.put("password", password);
					values.put("credentialId", "");
					page = send("POST", scriptedLoginAction, encodeForm(values), page.uri);
					loginPageSeen = true;
					passwordSubmitted = true;
					directCredentialPostAttempted = true;
					continue;
				}

				if (isLikelyDirectCredentialPostTarget(page.uri, page.body)) {
					final Map<String, String> values = new LinkedHashMap<>();
					values.put("username", user);
					values.put("password", password);
					values.put("credentialId", "");
					page = send("POST", page.uri, encodeForm(values), page.uri);
					loginPageSeen = true;
					passwordSubmitted = true;
					directCredentialPostAttempted = true;
					continue;
				}
			}

			break;
		}

		// Evaluate the final page
		if (page.status < 200 || page.status >= 300) {
			return fail("Final page returned HTTP " + page.status, page);
		}
		if (!isSameOrigin(page.uri, startUri)) {
			return fail("Final page is not on the web application host (still at identity provider?). "
					+ (loginPageSeen ? "Login form could not be completed." : "No login form found (JavaScript-based login is not supported)."),
					page);
		}
		if (findPasswordForm(HtmlForm.parseAll(page.body, page.uri)) != null) {
			return fail("Final page still contains a password form", page);
		}
		return new LoginSession(transport, page.uri, page.body);
	}

	/**
	 * Reason why the last {@link #login(URI, String, String)} returned null, e.g. "Login form was shown again after
	 * submitting the credentials (wrong username/password?)".
	 *
	 * @return null if the last login succeeded or threw an exception
	 */
	public String getLastFailureMessage() {
		return lastFailureMessage;
	}

	/**
	 * Result of a successful login: the logged in session of the web application with its cookies and CSRF token, to
	 * be used for further requests (headers "Cookie" and "X-CSRF-TOKEN").
	 *
	 * Each session has its own transport and cookie store, so it stays valid after further logins.
	 */
	public static final class LoginSession {
		private final HttpTransport transport;
		private final CookieManager cookieManager;
		private final URI finalPageUri;

		private String csrfToken;
		/** The request for the CSRF token is done once and only on demand */
		private boolean csrfTokenDetermined;

		private LoginSession(final HttpTransport transport, final URI finalPageUri, final String finalPageBody) {
			this.transport = transport;
			cookieManager = transport.getCookieManager();
			this.finalPageUri = finalPageUri;

			// Usually contained in the final page (meta tag), otherwise in a cookie
			csrfToken = findCsrfToken(finalPageBody);
			csrfTokenDetermined = csrfToken != null;
		}

		/**
		 * Returns the URI of the final page after the login (the main page of the web application).
		 *
		 * @return the URI
		 */
		public URI getFinalPageUri() {
			return finalPageUri;
		}

		/**
		 * Response of a request sent with {@link #send(String, URI, Map, String)}.
		 *
		 * @param statusCode
		 *            the HTTP status code
		 * @param body
		 *            the response body, empty if there is none
		 */
		public record SessionResponse(int statusCode, String body) {
		}

		/**
		 * Sends a request with this session: same transport as the login, so the same TLS trust (configured trust
		 * manager or JVM trust store), the same proxy and the session cookies (the "Cookie"
		 * header is added automatically and cookies set by the response are kept in the session). Redirects are not
		 * followed.
		 *
		 * @param method
		 *            HTTP method, e.g. "GET" or "POST"
		 * @param uri
		 *            the URI of the request
		 * @param headers
		 *            additional headers, e.g. "X-CSRF-TOKEN" and "Content-Type"; may be null
		 * @param body
		 *            request body, may be null (empty body)
		 * @return the response, also for HTTP error status codes
		 * @throws Exception
		 *             if the request fails (connection, TLS)
		 */
		public SessionResponse send(final String method, final URI uri, final Map<String, String> headers, final String body) throws Exception {
			final Map<String, String> requestHeaders = new LinkedHashMap<>();
			if (headers != null) {
				requestHeaders.putAll(headers);
			}
			final TransportResponse response = transport.execute(method, uri, requestHeaders, body);
			return new SessionResponse(response.status(), response.body());
		}

		/**
		 * CSRF token of the session (to be sent as header "X-CSRF-TOKEN").
		 *
		 * The token is taken from the final page (meta tag or JavaScript variable) or the cookies. If it is not found
		 * there, it is requested once with "X-CSRF-TOKEN: Fetch" (see {@link #fetchCsrfToken(URI)}).
		 *
		 * @return null if no token was found
		 */
		public synchronized String getCsrfToken() {
			if (!csrfTokenDetermined) {
				csrfTokenDetermined = true;
				// SAP/Spring style: the token is delivered on request with "X-CSRF-TOKEN: Fetch"
				csrfToken = fetchCsrfToken(finalPageUri);
			}
			return csrfToken;
		}

		/**
		 * Requests a (new) CSRF token for the given endpoint with this session by sending "X-CSRF-TOKEN: Fetch". Useful
		 * if a request with {@link #getCsrfToken()} was rejected. A delivered token replaces the token of this session.
		 *
		 * @param endpoint
		 *            the URI to request the token from, e.g. the endpoint that rejected the token
		 * @return the token or null if none was delivered
		 */
		public synchronized String fetchCsrfToken(final URI endpoint) {
			if (endpoint == null) {
				return null;
			}
			try {
				final Map<String, String> headers = new LinkedHashMap<>();
				headers.put("Accept", "*/*");
				headers.put("X-Requested-With", "XMLHttpRequest");
				headers.put("X-CSRF-TOKEN", "Fetch");
				headers.put("Referer", finalPageUri.toString());
				headers.put("Origin", finalPageUri.getScheme() + "://" + finalPageUri.getRawAuthority());
				final TransportResponse response = transport.execute("GET", endpoint, headers, null);
				final String headerToken = extractCsrfTokenFromHeaders(response.headers());
				final String token = headerToken != null ? headerToken : findCsrfToken(response.body());
				if (token != null) {
					csrfToken = token;
					csrfTokenDetermined = true;
				}
				return token;
			} catch (@SuppressWarnings("unused") final Exception e) {
				// No token from this endpoint
			}
			return null;
		}

		/**
		 * Searches a CSRF token in HTML (meta tag or JavaScript variable) and then in the cookies of the session.
		 */
		private String findCsrfToken(final String html) {
			if (html != null) {
				final Matcher metaMatcher = CSRF_META_PATTERN.matcher(html);
				if (metaMatcher.find()) {
					return decodeEntities(metaMatcher.group(1));
				}
				final Matcher jsMatcher = CSRF_JS_PATTERN.matcher(html);
				if (jsMatcher.find()) {
					return unescapeJsString(jsMatcher.group(1) != null ? jsMatcher.group(1) : jsMatcher.group(2));
				}
			}

			for (final HttpCookie cookie : cookieManager.getCookieStore().getCookies()) {
				final String name = cookie.getName().toLowerCase(Locale.ROOT);
				if ((name.contains("csrf") || name.contains("xsrf")) && cookie.getValue() != null && !cookie.getValue().isBlank()) {
					return cookie.getValue();
				}
			}
			return null;
		}

		@Override
		public String toString() {
			// Cookies and tokens must never appear in log output
			return "LoginSession @ " + finalPageUri;
		}
	}

	private static String extractCsrfTokenFromHeaders(final Map<String, String> headers) {
		for (final Map.Entry<String, String> header : headers.entrySet()) {
			final String name = header.getKey().toLowerCase(Locale.ROOT);
			if (!(name.contains("csrf") || name.contains("xsrf")) || header.getValue() == null) {
				continue;
			}
			// Several header lines of the same name are joined with ", " by the network library
			for (final String value : header.getValue().split(",\\s*")) {
				// "Required"/"Fetch" are protocol values of servers that demand or offer a token, no token itself
				if (value != null && !value.isBlank() && !"Required".equalsIgnoreCase(value.trim()) && !"Fetch".equalsIgnoreCase(value.trim())) {
					return value.trim();
				}
			}
		}
		return null;
	}

	/**
	 * Records the failure.
	 *
	 * @return always null (no session)
	 */
	private LoginSession fail(final String message, final Page page) {
		lastFailureMessage = message + " (final URL: " + page.uri + ", HTTP " + page.status + ")";
		return null;
	}

	private static HtmlForm findPasswordForm(final List<HtmlForm> forms) {
		for (final HtmlForm form : forms) {
			if (form.getFirstFieldNameOfType("password") != null) {
				return form;
			}
		}
		return null;
	}

	/**
	 * Detects forms that are submitted by JavaScript on page load (e.g. OIDC response_mode=form_post)
	 */
	private static HtmlForm findAutoPostForm(final List<HtmlForm> forms, final String body) {
		final boolean hasSubmitScript = AUTO_SUBMIT_SCRIPT_PATTERN.matcher(body).find();
		for (final HtmlForm form : forms) {
			if (form.fields.isEmpty() || !form.fields.stream().allMatch(field -> "hidden".equals(field.type) || "submit".equals(field.type))) {
				continue;
			}
			final boolean hasOidcFields = form.hasField("code") || form.hasField("id_token") || form.hasField("state") || form.hasField("SAMLResponse");
			if (hasSubmitScript || hasOidcFields) {
				return form;
			}
		}
		return null;
	}

	private static HtmlForm findUsernameOnlyForm(final List<HtmlForm> forms) {
		for (final HtmlForm form : forms) {
			if (findUsernameFieldName(form) != null) {
				return form;
			}
		}
		return null;
	}

	private static String findUsernameFieldName(final HtmlForm form) {
		String firstTextField = null;
		for (final HtmlField field : form.fields) {
			if ("text".equals(field.type) || "email".equals(field.type)) {
				if (USERNAME_FIELD_PATTERN.matcher(field.name).matches()) {
					return field.name;
				} else if (firstTextField == null) {
					firstTextField = field.name;
				}
			}
		}
		// Fallback for login forms with unusual field names: the only visible text field next to a password field
		return form.getFirstFieldNameOfType("password") != null ? firstTextField : null;
	}

	private Page submit(final HtmlForm form, final Map<String, String> values, final URI referer) throws Exception {
		final String encoded = encodeForm(values);
		if ("POST".equals(form.method)) {
			return send("POST", form.action, encoded, referer);
		} else {
			final String actionString = form.action.toString();
			final int fragmentIndex = actionString.indexOf('#');
			final String base = fragmentIndex >= 0 ? actionString.substring(0, fragmentIndex) : actionString;
			final String withoutQuery = base.contains("?") ? base.substring(0, base.indexOf('?')) : base;
			return send("GET", URI.create(withoutQuery + (encoded.isEmpty() ? "" : "?" + encoded)), null, referer);
		}
	}

	/**
	 * Sends a request and follows all redirects
	 */
	private Page send(final String initialMethod, final URI initialUri, final String initialFormBody, final URI referer) throws Exception {
		String method = initialMethod;
		URI uri = initialUri;
		String formBody = initialFormBody;
		URI currentReferer = referer;

		for (int redirectCount = 0; redirectCount <= MAX_REDIRECTS; redirectCount++) {
			final Map<String, String> headers = new LinkedHashMap<>();
			headers.put("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
			headers.put("Accept-Language", "de,en;q=0.8");
			if (currentReferer != null) {
				headers.put("Referer", currentReferer.toString());
			}
			final String body;
			if ("POST".equals(method)) {
				headers.put("Content-Type", "application/x-www-form-urlencoded");
				if (currentReferer != null) {
					headers.put("Origin", currentReferer.getScheme() + "://" + currentReferer.getRawAuthority());
				}
				body = formBody == null ? "" : formBody;
			} else {
				body = null;
			}

			final TransportResponse response = transport.execute(method, uri, headers, body);
			final int status = response.status();

			final String location = response.getHeader("Location");
			if (status >= 300 && status < 400 && location != null) {
				final URI nextUri = uri.resolve(location.trim().replace(" ", "%20"));
				if (!"http".equalsIgnoreCase(nextUri.getScheme()) && !"https".equalsIgnoreCase(nextUri.getScheme())) {
					throw new IllegalStateException("Redirect to unsupported URL scheme: " + nextUri);
				}
				if (status != 307 && status != 308) {
					method = "GET";
					formBody = null;
				}
				currentReferer = uri;
				uri = nextUri;
				continue;
			}

			return new Page(uri, status, response.body());
		}
		throw new IllegalStateException("Too many redirects (more than " + MAX_REDIRECTS + ")");
	}

	private static boolean isSameOrigin(final URI uri1, final URI uri2) {
		return uri1.getScheme().equalsIgnoreCase(uri2.getScheme())
				&& uri1.getHost().equalsIgnoreCase(uri2.getHost())
				&& effectivePort(uri1) == effectivePort(uri2);
	}

	private static boolean hasAnyFormField(final List<HtmlForm> forms) {
		for (final HtmlForm form : forms) {
			if (!form.fields.isEmpty()) {
				return true;
			}
		}
		return false;
	}

	private static boolean isLikelyDirectCredentialPostTarget(final URI uri, final String body) {
		if (isAuthorizationEndpoint(uri)) {
			return false;
		}

		final String path = uri.getPath() == null ? "" : uri.getPath().toLowerCase(Locale.ROOT);
		if (path.contains("/login-actions/authenticate") || path.contains("/login") || path.contains("/authenticate")) {
			return true;
		}
		final String lowerBody = body == null ? "" : body.toLowerCase(Locale.ROOT);
		return lowerBody.contains("session_code")
				|| lowerBody.contains("execution")
				|| lowerBody.contains("tab_id")
				|| lowerBody.contains("kc-form-login");
	}

	private static boolean isAuthorizationEndpoint(final URI uri) {
		final String path = uri.getPath() == null ? "" : uri.getPath().toLowerCase(Locale.ROOT);
		return path.contains("/protocol/openid-connect/auth")
				|| path.contains("/oauth2/authorize")
				|| path.endsWith("/authorize");
	}

	private static URI findClientSideRedirect(final Page page) {
		final Matcher metaRefreshMatcher = META_REFRESH_URL_PATTERN.matcher(page.body);
		if (metaRefreshMatcher.find()) {
			final URI resolved = resolveHttpUri(page.uri, metaRefreshMatcher.group(1));
			if (resolved != null) {
				return resolved;
			}
		}

		final Matcher jsLocationMatcher = JS_LOCATION_PATTERN.matcher(page.body);
		if (jsLocationMatcher.find()) {
			return resolveHttpUri(page.uri, jsLocationMatcher.group(1));
		}
		return null;
	}

	private static URI findScriptedLoginAction(final Page page) {
		final Matcher matcher = LOGIN_ACTION_PATTERN.matcher(page.body);
		if (!matcher.find()) {
			return null;
		}
		final String unescaped = unescapeJsString(matcher.group(1));
		return resolveHttpUri(page.uri, unescaped);
	}

	private static URI findIdpSelectionTarget(final Page page, final String targetLabel) {
		final String expected = targetLabel.trim().toLowerCase(Locale.ROOT);

		final Matcher providerMatcher = PROVIDER_PAIR_PATTERN.matcher(page.body);
		while (providerMatcher.find()) {
			final String displayName = unescapeJsString(providerMatcher.group(1));
			if (!displayName.trim().toLowerCase(Locale.ROOT).equals(expected)) {
				continue;
			}
			final URI resolved = resolveHttpUri(page.uri, unescapeJsString(providerMatcher.group(2)));
			if (resolved != null) {
				return resolved;
			}
		}

		final Matcher anchorMatcher = ANCHOR_PATTERN.matcher(page.body);
		while (anchorMatcher.find()) {
			final String label = normalizeText(anchorMatcher.group(2));
			if (!label.toLowerCase(Locale.ROOT).equals(expected)) {
				continue;
			}
			final Matcher hrefMatcher = HREF_ATTR_PATTERN.matcher(anchorMatcher.group(1));
			if (!hrefMatcher.find()) {
				continue;
			}
			final String href = hrefMatcher.group(1) != null ? hrefMatcher.group(1)
					: hrefMatcher.group(2) != null ? hrefMatcher.group(2) : hrefMatcher.group(3);
			final URI resolved = resolveHttpUri(page.uri, href);
			if (resolved != null) {
				return resolved;
			}
		}

		return null;
	}

	private static String unescapeJsString(final String value) {
		if (value == null) {
			return null;
		}
		return value.replace("\\/", "/").replace("\\u0026", "&").replace("\\\\", "\\");
	}

	private static URI resolveHttpUri(final URI baseUri, final String candidate) {
		if (candidate == null || candidate.isBlank()) {
			return null;
		}
		try {
			final URI resolved = baseUri.resolve(candidate.trim().replace(" ", "%20"));
			if ("http".equalsIgnoreCase(resolved.getScheme()) || "https".equalsIgnoreCase(resolved.getScheme())) {
				return resolved;
			}
		} catch (@SuppressWarnings("unused") final IllegalArgumentException e) {
			return null;
		}
		return null;
	}

	private static int effectivePort(final URI uri) {
		if (uri.getPort() != -1) {
			return uri.getPort();
		}
		return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
	}

	private static String encodeForm(final Map<String, String> values) {
		final StringBuilder builder = new StringBuilder();
		for (final Map.Entry<String, String> entry : values.entrySet()) {
			if (builder.length() > 0) {
				builder.append('&');
			}
			builder.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8))
					.append('=')
					.append(URLEncoder.encode(entry.getValue() == null ? "" : entry.getValue(), StandardCharsets.UTF_8));
		}
		return builder.toString();
	}

	/**
	 * Tries to find a login error message on the identity provider page (e.g. Keycloak "Invalid username or password.")
	 */
	private static String extractErrorText(final String html) {
		final Matcher matcher = ERROR_TEXT_PATTERN.matcher(html);
		while (matcher.find()) {
			final String text = normalizeText(matcher.group(2));
			if (!text.isEmpty()) {
				return text.length() > 200 ? text.substring(0, 200) + "..." : text;
			}
		}
		return null;
	}

	private static String normalizeText(final String html) {
		return WHITESPACE_PATTERN.matcher(decodeEntities(HTML_TAG_PATTERN.matcher(html).replaceAll(" "))).replaceAll(" ").trim();
	}

	private static String decodeEntities(final String text) {
		if (text == null || text.indexOf('&') < 0) {
			return text;
		}
		final Matcher matcher = HTML_ENTITY_PATTERN.matcher(text);
		final StringBuilder result = new StringBuilder();
		while (matcher.find()) {
			final String entity = matcher.group(1);
			final String replacement;
			if (entity.startsWith("#x") || entity.startsWith("#X")) {
				replacement = new String(Character.toChars(Integer.parseInt(entity.substring(2), 16)));
			} else if (entity.startsWith("#")) {
				replacement = new String(Character.toChars(Integer.parseInt(entity.substring(1))));
			} else {
				replacement = switch (entity) {
					case "amp" -> "&";
					case "lt" -> "<";
					case "gt" -> ">";
					case "quot" -> "\"";
					case "apos" -> "'";
					default -> " ";
				};
			}
			matcher.appendReplacement(result, Matcher.quoteReplacement(replacement));
		}
		matcher.appendTail(result);
		return result.toString();
	}

	private record Page(URI uri, int status, String body) {
	}

	/**
	 * Sends the requests of a login and its login session with {@link HttpUtilities}: own cookie
	 * store per login session, redirects are not followed (the login flow follows them itself to see every hop), proxy
	 * and TLS trust as configured.
	 * <p>
	 * HTTP/2 is requested (with transparent fallback to HTTP/1.1), so the requests are sent with
	 * java.net.http.HttpClient. Its HTTP/1.1 transport HttpURLConnection would silently drop the "Origin" header, which
	 * is checked by the CSRF protection of many identity providers and web applications.
	 * </p>
	 */
	private static final class HttpTransport {
		private final CookieManager cookieManager = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
		private final String proxyUrl;
		private final TrustManager trustManager;
		private final int timeoutMillis;
		private final String userAgent;

		HttpTransport(final String proxyUrl, final TrustManager trustManager, final Duration timeout, final String userAgent) {
			this.proxyUrl = proxyUrl;
			this.trustManager = trustManager;
			this.userAgent = userAgent;
			timeoutMillis = (int) Math.min(Integer.MAX_VALUE, Math.max(0, timeout.toMillis()));
		}

		CookieManager getCookieManager() {
			return cookieManager;
		}

		/**
		 * Sends a request without following redirects.
		 *
		 * @param method
		 *            HTTP method, e.g. "GET" or "POST"
		 * @param headers
		 *            request headers, may be null; null values are skipped
		 * @param body
		 *            request body, null for none
		 */
		TransportResponse execute(final String method, final URI uri, final Map<String, String> headers, final String body) throws Exception {
			final HttpRequest request = new HttpRequest(HttpMethod.getHttpMethodByName(method), uri.toString());
			request.setHttpVersion(HttpVersion.HTTP_2);
			request.setMaxRedirects(0);
			request.setConnectionTimeoutMillis(timeoutMillis);
			request.setReadTimeoutMillis(timeoutMillis);
			request.addHeader("User-Agent", userAgent);
			if (headers != null) {
				for (final Map.Entry<String, String> header : headers.entrySet()) {
					if (header.getValue() != null) {
						request.addHeader(header.getKey(), header.getValue());
					}
				}
			}

			// The cookie store selects the cookies matching domain, path and "Secure" of the URI
			final List<String> cookieHeaderValues = cookieManager.get(uri, Collections.emptyMap()).get("Cookie");
			if (cookieHeaderValues != null) {
				for (final String cookieHeaderValue : cookieHeaderValues) {
					for (final String cookie : cookieHeaderValue.split(";\\s*")) {
						final int equalsIndex = cookie.indexOf('=');
						if (equalsIndex > 0) {
							request.addCookieData(cookie.substring(0, equalsIndex), cookie.substring(equalsIndex + 1));
						}
					}
				}
			}

			if (body != null) {
				request.setRequestBody(body);
			}

			final HttpResponse response = HttpUtilities.executeHttpRequest(request, HttpUtilities.resolveProxy(proxyUrl, uri), trustManager, false);
			final TransportResponse transportResponse = new TransportResponse(response.getHttpCode(), response.getContent() == null ? "" : response.getContent(),
					response.getHeaders() == null ? Collections.emptyMap() : response.getHeaders());

			// The network library joins several "Set-Cookie" header lines with a line break
			final String setCookieData = transportResponse.getHeader("Set-Cookie");
			if (setCookieData != null) {
				final Map<String, List<String>> setCookieHeaders = new LinkedHashMap<>();
				setCookieHeaders.put("Set-Cookie", Arrays.stream(setCookieData.split("\n")).filter(line -> !line.isBlank()).toList());
				cookieManager.put(uri, setCookieHeaders);
			}
			return transportResponse;
		}
	}

	/**
	 * Response of {@link HttpTransport#execute(String, URI, Map, String)}.
	 *
	 * @param headers
	 *            response headers; several lines of the same name are joined (", ", for "Set-Cookie" with a line break)
	 */
	private record TransportResponse(int status, String body, Map<String, String> headers) {
		/**
		 * Header value by case insensitive name, null if missing.
		 */
		String getHeader(final String name) {
			for (final Map.Entry<String, String> header : headers.entrySet()) {
				if (header.getKey() != null && header.getKey().equalsIgnoreCase(name)) {
					return header.getValue();
				}
			}
			return null;
		}
	}

	private record HtmlField(String name, String type, String value, boolean checked) {
	}

	/**
	 * Minimal regex based HTML form parser, sufficient for typical identity provider login pages
	 */
	private static class HtmlForm {
		private static final Pattern FORM_PATTERN = Pattern.compile("(?is)<form\\b([^>]*)>(.*?)</form\\s*>");
		private static final Pattern FIELD_PATTERN = Pattern.compile("(?is)<(input|button|select|textarea)\\b([^>]*)>");
		private static final Pattern ATTRIBUTE_PATTERN = Pattern.compile("([a-zA-Z_:][-a-zA-Z0-9_:.]*)\\s*(?:=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s\"'=<>`]+)))?");

		private final URI action;
		private final String method;
		private final List<HtmlField> fields = new ArrayList<>();

		private HtmlForm(final URI action, final String method) {
			this.action = action;
			this.method = method;
		}

		static List<HtmlForm> parseAll(final String html, final URI pageUri) {
			final List<HtmlForm> forms = new ArrayList<>();
			final Matcher formMatcher = FORM_PATTERN.matcher(html);
			while (formMatcher.find()) {
				final Map<String, String> formAttributes = parseAttributes(formMatcher.group(1));
				final String actionValue = formAttributes.getOrDefault("action", "").trim();
				URI action;
				try {
					action = actionValue.isEmpty() ? pageUri : pageUri.resolve(actionValue.replace(" ", "%20"));
				} catch (@SuppressWarnings("unused") final IllegalArgumentException e) {
					continue;
				}
				final String method = formAttributes.getOrDefault("method", "get").trim().toUpperCase(Locale.ROOT);
				final HtmlForm form = new HtmlForm(action, "POST".equals(method) ? "POST" : "GET");

				final Matcher fieldMatcher = FIELD_PATTERN.matcher(formMatcher.group(2));
				while (fieldMatcher.find()) {
					final String tag = fieldMatcher.group(1).toLowerCase(Locale.ROOT);
					final Map<String, String> attributes = parseAttributes(fieldMatcher.group(2));
					final String name = attributes.get("name");
					if (name == null || name.isEmpty() || attributes.containsKey("disabled")) {
						continue;
					}
					final String type = switch (tag) {
						case "button" -> attributes.getOrDefault("type", "submit").toLowerCase(Locale.ROOT);
						case "input" -> attributes.getOrDefault("type", "text").toLowerCase(Locale.ROOT);
						default -> tag;
					};
					form.fields.add(new HtmlField(name, type, attributes.getOrDefault("value", ""), attributes.containsKey("checked")));
				}
				forms.add(form);
			}
			return forms;
		}

		private static Map<String, String> parseAttributes(final String attributeString) {
			final Map<String, String> attributes = new LinkedHashMap<>();
			final Matcher matcher = ATTRIBUTE_PATTERN.matcher(attributeString);
			while (matcher.find()) {
				String value = matcher.group(2);
				if (value == null) {
					value = matcher.group(3);
				}
				if (value == null) {
					value = matcher.group(4);
				}
				attributes.putIfAbsent(matcher.group(1).toLowerCase(Locale.ROOT), value == null ? "" : decodeEntities(value));
			}
			return attributes;
		}

		boolean hasField(final String name) {
			return fields.stream().anyMatch(field -> field.name.equals(name));
		}

		String getFirstFieldNameOfType(final String type) {
			return fields.stream().filter(field -> type.equals(field.type)).map(HtmlField::name).findFirst().orElse(null);
		}

		/**
		 * Values a browser would send without user interaction (only the first submit button is "clicked")
		 */
		Map<String, String> getDefaultValues() {
			final Map<String, String> values = new LinkedHashMap<>();
			boolean submitButtonUsed = false;
			for (final HtmlField field : fields) {
				switch (field.type) {
					case "submit", "image" -> {
						if (!submitButtonUsed) {
							values.put(field.name, field.value);
							submitButtonUsed = true;
						}
					}
					case "checkbox", "radio" -> {
						if (field.checked) {
							values.put(field.name, field.value.isEmpty() ? "on" : field.value);
						}
					}
					case "reset", "button", "file", "select" -> {
						// Not sent by this simple client
					}
					default -> values.put(field.name, field.value);
				}
			}
			return values;
		}
	}
}
