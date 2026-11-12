package de.soderer.network;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import de.soderer.network.HttpRequest.UploadFileAttachment;
import de.soderer.network.trustmanager.TrustManagerUtilities;
import de.soderer.network.utilities.CaseInsensitiveLinkedMap;

/**
 * Executes HTTP requests and provides HTTP related helper methods.
 * <p>
 * HTTP/1.1 requests are sent via {@link HttpURLConnection}, HTTP/2 requests (see
 * {@link HttpRequest#getHttpVersion()}) via {@link HttpClient}, which falls back to HTTP/1.1 if the
 * server does not support HTTP/2.
 * </p>
 * <p>
 * Requests can be sent through a proxy (with optional proxy authentication) and with a custom
 * {@link TrustManager} for TLS certificate checks. Redirects are followed as configured in the
 * request, without sending credentials to other origins.
 * </p>
 */
public class HttpUtilities {
	/**
	 * Utility class, not to be instantiated.
	 */
	private HttpUtilities() {
	}

	private static boolean debugLog = false;
	private static String TLS_VERSION = "TLS"; // Also possible definitions "TLSv1.2", "TLSv1.3"

	// HttpURLConnection does not define constants for these two redirect status codes
	private static final int HTTP_TEMPORARY_REDIRECT = 307;
	private static final int HTTP_PERMANENT_REDIRECT = 308;

	private static HostnameVerifier TRUSTALLHOSTNAMES_HOSTNAMEVERIFIER = (hostname, session) -> true;

	/**
	 * Executes a request. Uses the system's default proxy, if set on JVM start, and the system's
	 * default truststore to check TLS server certificates.
	 *
	 * @param httpRequest
	 *            the request
	 * @return the response, also for HTTP error status codes
	 * @throws Exception
	 *             if the request cannot be sent or the response cannot be read
	 */
	public static HttpResponse executeHttpRequest(final HttpRequest httpRequest) throws Exception {
		return executeHttpRequest(httpRequest, null, (TrustManager) null, false);
	}

	/**
	 * Executes a request through a proxy. Uses the system's default truststore to check TLS server
	 * certificates.
	 *
	 * @param httpRequest
	 *            the request
	 * @param proxy
	 *            the proxy, null for the system's default proxy, {@link Proxy#NO_PROXY} for a direct
	 *            connection
	 * @return the response, also for HTTP error status codes
	 * @throws Exception
	 *             if the request cannot be sent or the response cannot be read
	 */
	public static HttpResponse executeHttpRequest(final HttpRequest httpRequest, final Proxy proxy) throws Exception {
		return executeHttpRequest(httpRequest, proxy, (TrustManager) null, false);
	}

	/**
	 * Executes a request, checking TLS server certificates only against the given truststore.
	 *
	 * @param httpRequest
	 *            the request
	 * @param proxy
	 *            the proxy, null for the system's default proxy, {@link Proxy#NO_PROXY} for a direct
	 *            connection
	 * @param trustedKeyStore
	 *            the trusted certificates
	 * @return the response, also for HTTP error status codes
	 * @throws Exception
	 *             if the truststore is empty, or the request cannot be sent or the response cannot be read
	 */
	public static HttpResponse executeHttpRequest(final HttpRequest httpRequest, final Proxy proxy,
			final KeyStore trustedKeyStore) throws Exception {
		if (trustedKeyStore.size() <= 0) {
			throw new Exception("No trusted certificate aliases found in defined trusted keystore");
		} else {
			return executeHttpRequest(httpRequest, proxy,
					TrustManagerUtilities.createTrustManagerForKeyStore(trustedKeyStore), false);
		}
	}

	/**
	 * Executes a request with a custom TLS certificate check.
	 *
	 * @param httpRequest
	 *            the request
	 * @param proxy
	 *            the proxy, null for the system's default proxy, {@link Proxy#NO_PROXY} for a direct
	 *            connection
	 * @param trustManager
	 *            the TLS certificate check, null for the system's default truststore
	 * @param deactivateHostnameVerification
	 *            true to accept server certificates issued for other host names (insecure)
	 * @return the response, also for HTTP error status codes
	 * @throws Exception
	 *             if the request cannot be sent or the response cannot be read
	 */
	public static HttpResponse executeHttpRequest(final HttpRequest httpRequest, final Proxy proxy,
			final TrustManager trustManager, final boolean deactivateHostnameVerification) throws Exception {
		return executeHttpRequest(httpRequest, proxy, null, null, trustManager, deactivateHostnameVerification);
	}

	/**
	 * Executes a request through an authenticating proxy with a custom TLS certificate check.
	 *
	 * @param httpRequest
	 *            the request
	 * @param proxy
	 *            the proxy, null for the system's default proxy, {@link Proxy#NO_PROXY} for a direct
	 *            connection
	 * @param proxyUsername
	 *            user name for the proxy, null for no proxy authentication
	 * @param proxyPassword
	 *            password for the proxy
	 * @param trustManager
	 *            the TLS certificate check, null for the system's default truststore
	 * @param deactivateHostnameVerification
	 *            true to accept server certificates issued for other host names (insecure)
	 * @return the response, also for HTTP error status codes
	 * @throws Exception
	 *             if the request cannot be sent or the response cannot be read
	 */
	public static HttpResponse executeHttpRequest(final HttpRequest httpRequest, final Proxy proxy,
			final String proxyUsername, final String proxyPassword, final TrustManager trustManager,
			final boolean deactivateHostnameVerification) throws Exception {
		return executeHttpRequest(httpRequest, proxy, proxyUsername, proxyPassword, trustManager, deactivateHostnameVerification, 0, false);
	}

	private static HttpResponse executeHttpRequest(final HttpRequest httpRequest, final Proxy proxy,
			final String proxyUsername, final String proxyPassword, final TrustManager trustManager,
			final boolean deactivateHostnameVerification, final int redirectCount, final boolean credentialsDroppedSoFar) throws Exception {
		try {
			String requestedUrl = httpRequest.getUrlWithProtocol();
			if (requestedUrl.indexOf('#') >= 0) {
				// The fragment is never sent to the server. Removed here, so that added parameters do not end up
				// within the fragment (e.g. "page#top?a=1") and "#" before "?" cannot break the parameter split.
				requestedUrl = requestedUrl.substring(0, requestedUrl.indexOf('#'));
			}

			// Check for already in URL included GET parameters
			String parametersFromUrl;
			if (requestedUrl.contains("?")) {
				if (requestedUrl.contains("#")) {
					parametersFromUrl = requestedUrl.substring(requestedUrl.indexOf("?") + 1,
							requestedUrl.indexOf("#"));
					requestedUrl = requestedUrl.substring(0, requestedUrl.indexOf("?"));
				} else {
					parametersFromUrl = requestedUrl.substring(requestedUrl.indexOf("?") + 1);
					requestedUrl = requestedUrl.substring(0, requestedUrl.indexOf("?"));
				}
			} else {
				parametersFromUrl = "";
			}

			// Prepare GET parameters data
			if (httpRequest.getUrlParameters() != null && httpRequest.getUrlParameters().size() > 0) {
				final String getParameterString = convertToParameterString(httpRequest.getUrlParameters(),
						httpRequest.getEncoding());
				if (parametersFromUrl.length() > 0) {
					requestedUrl += "?" + parametersFromUrl + "&" + getParameterString;
				} else {
					requestedUrl += "?" + getParameterString;
				}
			} else if (parametersFromUrl.length() > 0) {
				requestedUrl += "?" + parametersFromUrl;
			}

			if (debugLog) {
				System.out.println("Requested URL: " + requestedUrl);
			}

			// HttpURLConnection only supports HTTP/1.1, so HTTP/2 requests are sent via java.net.http.HttpClient.
			// Everything after receiving the response (redirects, cookies, downloads, ...) is transport independent.
			final ReceivedResponse receivedResponse;
			if (httpRequest.getHttpVersion() == HttpVersion.HTTP_2) {
				receivedResponse = sendWithHttpClient(httpRequest, requestedUrl, proxy, proxyUsername, proxyPassword,
						trustManager, deactivateHostnameVerification);
			} else {
				receivedResponse = sendWithHttpUrlConnection(httpRequest, requestedUrl, proxy, proxyUsername, proxyPassword,
						trustManager, deactivateHostnameVerification);
			}

			try (receivedResponse) {
				// urlConnection.getHeaderField(name) only returns a single value per header name, which silently
				// drops data for headers that are legitimately sent multiple times (most importantly Set-Cookie,
				// where servers typically send one header per cookie). Join multi-valued headers with ", " instead,
				// except Set-Cookie, whose values are joined with "\n" so cookie parsing below can split them apart
				// again without confusing a cookie's own internal ";"-separated attributes with cookie boundaries.
				final Map<String, String> headers = new CaseInsensitiveLinkedMap<>();
				for (final Entry<String, List<String>> headerFieldEntry : receivedResponse.getHeaderFields().entrySet()) {
					final String headerName = headerFieldEntry.getKey();
					if (headerName == null || headerName.startsWith(":")) {
						// The status line itself is exposed as a null-keyed entry by HttpURLConnection,
						// HTTP/2 pseudo headers (e.g. ":status") are no real response headers. Skip both.
						continue;
					}
					final List<String> headerValues = headerFieldEntry.getValue();
					final String joinedValue;
					if (HttpConstants.HTTPHEADERNAME_DOWNLOAD_COOKIE.equalsIgnoreCase(headerName)) {
						joinedValue = String.join("\n", headerValues);
					} else {
						joinedValue = String.join(", ", headerValues);
					}
					headers.put(headerName, joinedValue);
				}

				Charset encoding = StandardCharsets.UTF_8;
				if (headers.containsKey(HttpConstants.HTTPHEADERNAME_CONTENTTYPE)) {
					String contentType = headers.get(HttpConstants.HTTPHEADERNAME_CONTENTTYPE);
					if (contentType != null && contentType.toLowerCase(Locale.ROOT).contains("charset=")) {
						contentType = contentType.toLowerCase(Locale.ROOT);
						encoding = Charset.forName(contentType.substring(contentType.indexOf("charset=") + 8).trim());
					}
				}

				Map<String, String> cookiesMap = null;
				if (headers.containsKey(HttpConstants.HTTPHEADERNAME_DOWNLOAD_COOKIE)) {
					final String cookiesData = headers.get(HttpConstants.HTTPHEADERNAME_DOWNLOAD_COOKIE);
					if (cookiesData != null) {
						cookiesMap = new LinkedHashMap<>();
						// Each line here is one full Set-Cookie header value (joined above with "\n" for multiple headers).
						// Only its first ";"-segment is the actual "name=value" pair; everything after that are
						// cookie attributes (Path, Domain, Expires, Max-Age, Secure, HttpOnly, SameSite, ...) and
						// must not be treated as additional cookies.
						for (final String cookieHeaderValue : cookiesData.split("\n")) {
							if (NetworkUtilities.isBlank(cookieHeaderValue)) {
								continue;
							}
							final String nameValuePart = cookieHeaderValue.split(";", 2)[0].trim();
							final int equalsIndex = nameValuePart.indexOf('=');
							if (equalsIndex > 0) {
								// Split on the first "=" only, since the cookie value itself may legitimately contain "="
								final String cookieName = nameValuePart.substring(0, equalsIndex).trim();
								final String cookieValue = nameValuePart.substring(equalsIndex + 1).trim();
								cookiesMap.put(urlDecode(cookieName, StandardCharsets.UTF_8),
										urlDecode(cookieValue, StandardCharsets.UTF_8));
							}
						}
					}
				}

				final int httpResponseCode = receivedResponse.getStatusCode();
				final boolean isRedirectResponseCode = httpResponseCode == HttpURLConnection.HTTP_MOVED_TEMP
						|| httpResponseCode == HttpURLConnection.HTTP_MOVED_PERM
						|| httpResponseCode == HttpURLConnection.HTTP_SEE_OTHER
						|| httpResponseCode == HTTP_TEMPORARY_REDIRECT
						|| httpResponseCode == HTTP_PERMANENT_REDIRECT;
				if (isRedirectResponseCode && httpRequest.getMaxRedirects() != 0) {
					// Optionally follow redirections (HttpCodes 301, 302, 303, 307 and 308)
					// NOTE: this check must happen before the "httpResponseCode < 400" success branch below,
					// since 301/302/303 are all < 400 and would otherwise always be swallowed there first.
					final int maxRedirects = httpRequest.getMaxRedirects();
					if (maxRedirects > 0 && redirectCount >= maxRedirects) {
						throw new Exception("Too many redirects (>" + maxRedirects + ") while requesting URL '" + httpRequest.getUrlWithProtocol() + "'");
					}
					final String redirectUrl = headers.get("Location");
					if (NetworkUtilities.isNotBlank(redirectUrl)) {
						// Resolve the Location value against the requested URL, since servers are allowed to
						// send a relative redirect target (path only, without scheme/host).
						final URI redirectUri = URI.create(requestedUrl).resolve(redirectUrl);

						// Credentials (Authorization header, Cookies) must only be forwarded to a redirect
						// target on the SAME origin (scheme + host + port). Otherwise the server issuing the
						// redirect (or an open-redirect flaw on its side) could exfiltrate them to an arbitrary
						// third-party host. Non-credential headers are still carried over regardless of origin.
						final boolean sameOrigin = isSameOrigin(URI.create(requestedUrl), redirectUri);

						final boolean hadAuthorizationHeader = httpRequest.getHeaders() != null && httpRequest.getHeaders().keySet().stream()
								.anyMatch(headerName -> HttpConstants.HTTPHEADERNAME_AUTHORIZATION.equalsIgnoreCase(headerName));
						final boolean hadCookies = httpRequest.getCookieData() != null && httpRequest.getCookieData().size() > 0;
						final boolean credentialsDroppedThisHop = !sameOrigin && (hadAuthorizationHeader || hadCookies);

						// Determine the HTTP method to use for the redirected request:
						// - 303 (See Other) always switches to GET and drops the body (RFC 7231 6.4.4).
						// - 301/302 for an original POST also downgrade to GET/no body; this is not strictly
						//   required by RFC 7231 but is the behaviour established by browsers and most HTTP
						//   client libraries, so servers generally rely on it.
						// - 307/308 (and 301/302 for methods other than POST, e.g. GET/HEAD) always preserve
						//   the original method and body.
						final HttpMethod originalMethod = httpRequest.getRequestMethod();
						final HttpMethod redirectedMethod;
						final boolean dropBody;
						if (httpResponseCode == HttpURLConnection.HTTP_SEE_OTHER) {
							redirectedMethod = HttpMethod.GET;
							dropBody = true;
						} else if ((httpResponseCode == HttpURLConnection.HTTP_MOVED_PERM
								|| httpResponseCode == HttpURLConnection.HTTP_MOVED_TEMP)
								&& originalMethod == HttpMethod.POST) {
							redirectedMethod = HttpMethod.GET;
							dropBody = true;
						} else {
							redirectedMethod = originalMethod;
							dropBody = false;
						}

						final HttpRequest redirectedHttpRequest = new HttpRequest(redirectedMethod, redirectUri.toString());

						if (!dropBody) {
							if (httpRequest.getRequestBodyContentStream() != null) {
								// An InputStream-based request body has already been (partially) consumed while
								// sending the original request, so it cannot be safely re-read for the redirected
								// request. Silently sending the redirect without it would just hide the problem.
								throw new Exception("Cannot follow " + httpResponseCode + " redirect for URL '"
										+ httpRequest.getUrlWithProtocol() + "' to '" + redirectUri
										+ "': the request body was supplied as an InputStream, which cannot be re-sent for a redirected request.");
							}
							if (httpRequest.getRequestBody() != null) {
								redirectedHttpRequest.setRequestBody(httpRequest.getRequestBody());
							}
							for (final Entry<String, List<Object>> postParameterEntry : httpRequest.getPostParameters().entrySet()) {
								for (final Object value : postParameterEntry.getValue()) {
									redirectedHttpRequest.addPostParameter(postParameterEntry.getKey(), value);
								}
							}
							for (final UploadFileAttachment uploadFileAttachment : httpRequest.getUploadFileAttachments()) {
								redirectedHttpRequest.addUploadFileData(uploadFileAttachment.getHtmlInputName(),
										uploadFileAttachment.getFileName(), uploadFileAttachment.getData());
							}
						}

						if (httpRequest.getHeaders() != null) {
							for (final Entry<String, String> headerEntry : httpRequest.getHeaders().entrySet()) {
								if (!sameOrigin && HttpConstants.HTTPHEADERNAME_AUTHORIZATION.equalsIgnoreCase(headerEntry.getKey())) {
									// Drop credentials when redirected to a different origin
									continue;
								}
								redirectedHttpRequest.addHeader(headerEntry.getKey(), headerEntry.getValue());
							}
						}
						if (sameOrigin && httpRequest.getCookieData() != null) {
							for (final Entry<String, String> cookieEntry : httpRequest.getCookieData().entrySet()) {
								redirectedHttpRequest.addCookieData(cookieEntry.getKey(), cookieEntry.getValue());
							}
						}
						redirectedHttpRequest.setEncoding(httpRequest.getEncoding());
						redirectedHttpRequest.setConnectionTimeoutMillis(httpRequest.getConnectTimeoutMillis());
						redirectedHttpRequest.setReadTimeoutMillis(httpRequest.getReadTimeoutMillis());
						// The redirected request uses the same protocol version as the original one
						redirectedHttpRequest.setHttpVersion(httpRequest.getHttpVersion());
						// Propagate the same hop-limit semantics (unlimited stays unlimited, a finite limit stays the same limit)
						redirectedHttpRequest.setMaxRedirects(maxRedirects);
						return executeHttpRequest(redirectedHttpRequest, proxy, proxyUsername, proxyPassword, trustManager,
								deactivateHostnameVerification, redirectCount + 1, credentialsDroppedSoFar || credentialsDroppedThisHop);
					} else {
						throw new Exception("Redirection url was empty");
					}
				} else if (httpResponseCode < HttpURLConnection.HTTP_BAD_REQUEST) {
					final String finalUrlForResponse = redirectCount > 0 ? requestedUrl : null;
					if (httpRequest.getDownloadStream() != null && 200 <= httpResponseCode && httpResponseCode <= 299) {
						NetworkUtilities.copy(receivedResponse.getBodyStream(), httpRequest.getDownloadStream());
						return new HttpResponse(receivedResponse.getIpAddress(), httpResponseCode, receivedResponse.getStatusMessage(),
								"File downloaded", receivedResponse.getContentType(), headers, cookiesMap,
								redirectCount, finalUrlForResponse, credentialsDroppedSoFar, null, receivedResponse.getHttpVersion());
					} else if (httpRequest.getDownloadFile() != null && 200 <= httpResponseCode
							&& httpResponseCode <= 299) {
						try (FileOutputStream downloadFileOutputStream = new FileOutputStream(
								httpRequest.getDownloadFile())) {
							NetworkUtilities.copy(receivedResponse.getBodyStream(), downloadFileOutputStream);
							return new HttpResponse(receivedResponse.getIpAddress(), httpResponseCode, receivedResponse.getStatusMessage(),
									"File downloaded", receivedResponse.getContentType(), headers, cookiesMap,
									redirectCount, finalUrlForResponse, credentialsDroppedSoFar, httpRequest.getDownloadFile().getAbsolutePath(), receivedResponse.getHttpVersion());
						} catch (final Exception e) {
							if (httpRequest.getDownloadFile().exists()) {
								httpRequest.getDownloadFile().delete();
							}
							throw e;
						}
					} else if (httpRequest.getDownloadTarget() != null && 200 <= httpResponseCode && httpResponseCode <= 299
							&& isFileDownloadResponse(headers)) {
						final File targetFile = resolveDownloadTargetFile(httpRequest.getDownloadTarget(), headers, requestedUrl);
						try (FileOutputStream downloadFileOutputStream = new FileOutputStream(targetFile)) {
							NetworkUtilities.copy(receivedResponse.getBodyStream(), downloadFileOutputStream);
							return new HttpResponse(receivedResponse.getIpAddress(), httpResponseCode, receivedResponse.getStatusMessage(),
									"File downloaded to '" + targetFile.getAbsolutePath() + "'", receivedResponse.getContentType(), headers, cookiesMap,
									redirectCount, finalUrlForResponse, credentialsDroppedSoFar, targetFile.getAbsolutePath(), receivedResponse.getHttpVersion());
						} catch (final Exception e) {
							if (targetFile.exists()) {
								targetFile.delete();
							}
							throw e;
						}
					} else {
						try (BufferedReader httpResponseContentReader = new BufferedReader(
								new InputStreamReader(receivedResponse.getBodyStream(), encoding))) {
							final StringBuilder httpResponseContent = new StringBuilder();
							String httpResponseContentLine;
							while ((httpResponseContentLine = httpResponseContentReader.readLine()) != null) {
								if (httpResponseContent.length() > 0) {
									httpResponseContent.append("\n");
								}
								httpResponseContent.append(httpResponseContentLine);
							}
							return new HttpResponse(receivedResponse.getIpAddress(), httpResponseCode, receivedResponse.getStatusMessage(),
									httpResponseContent.toString(), receivedResponse.getContentType(), headers, cookiesMap,
									redirectCount, finalUrlForResponse, credentialsDroppedSoFar, null, receivedResponse.getHttpVersion());
						} catch (@SuppressWarnings("unused") final Exception e) {
							return new HttpResponse(receivedResponse.getIpAddress(), httpResponseCode, receivedResponse.getStatusMessage(), null,
									null, headers, cookiesMap, redirectCount, finalUrlForResponse, credentialsDroppedSoFar, null, receivedResponse.getHttpVersion());
						}
					}
				} else {
					final String finalUrlForResponse = redirectCount > 0 ? requestedUrl : null;
					try (BufferedReader httpResponseContentReader = new BufferedReader(
							new InputStreamReader(receivedResponse.getBodyStream(), encoding))) {
						final StringBuilder httpResponseContent = new StringBuilder();
						String httpResponseContentLine;
						while ((httpResponseContentLine = httpResponseContentReader.readLine()) != null) {
							if (httpResponseContent.length() > 0) {
								httpResponseContent.append("\n");
							}
							httpResponseContent.append(httpResponseContentLine);
						}
						return new HttpResponse(receivedResponse.getIpAddress(), httpResponseCode, receivedResponse.getStatusMessage(),
								httpResponseContent.toString(), receivedResponse.getContentType(), headers, cookiesMap,
								redirectCount, finalUrlForResponse, credentialsDroppedSoFar, null, receivedResponse.getHttpVersion());
					} catch (@SuppressWarnings("unused") final Exception e) {
						return new HttpResponse(receivedResponse.getIpAddress(), httpResponseCode, receivedResponse.getStatusMessage(), null, null,
								headers, cookiesMap, redirectCount, finalUrlForResponse, credentialsDroppedSoFar, null, receivedResponse.getHttpVersion());
					}
				}
			}
		} catch (final UnknownHostException e) {
			throw new Exception("Unknown host '" + e.getMessage() + "'", e);
		} catch (final SSLHandshakeException e) {
			final Throwable cause = e.getCause();
			if (cause instanceof CertificateException && cause.getMessage() != null
					&& cause.getMessage().toLowerCase(Locale.ROOT).contains("no name matching")) {
				throw new Exception("Cannot validate TLS server certificate for URL '" + httpRequest.getUrlWithProtocol() + "' (Hostname error)", e);
			} else {
				throw new Exception("Cannot validate TLS server certificate for URL '" + httpRequest.getUrlWithProtocol() + "' (Certificate chain error)", e);
			}
		} catch (final Exception e) {
			throw e;
		} finally {
			httpRequest.setHttpURLConnection(null);
		}
	}

	/**
	 * Sends a request via {@link HttpURLConnection} (HTTP/1.1) without following redirects.
	 */
	private static ReceivedResponse sendWithHttpUrlConnection(final HttpRequest httpRequest, final String requestedUrl,
			final Proxy proxy, final String proxyUsername, final String proxyPassword, final TrustManager trustManager,
			final boolean deactivateHostnameVerification) throws Exception {
		final HttpURLConnection urlConnection = (HttpURLConnection) URI.create(requestedUrl).toURL()
				.openConnection(proxy == null ? Proxy.NO_PROXY : proxy);
		httpRequest.setHttpURLConnection(urlConnection);

		urlConnection.setInstanceFollowRedirects(false);
		if (httpRequest.getRequestMethod() != null) {
			urlConnection.setRequestMethod(httpRequest.getRequestMethod().name());
		}
		if (proxy != null && !proxy.equals(Proxy.NO_PROXY) && proxyUsername != null && proxyPassword != null) {
			urlConnection.setRequestProperty(HttpConstants.HTTPHEADERNAME_PROXY_AUTHORIZATION,
					createProxyAuthorizationHeaderValue(proxyUsername, proxyPassword));
		}

		if (requestedUrl.toLowerCase(Locale.ROOT).startsWith(HttpConstants.SECURE_HTTP_PROTOCOL_SIGN)) {
			if (trustManager != null) {
				// Use special trustmanager
				final SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
				sslContext.init(null, new TrustManager[] { trustManager }, new SecureRandom());
				final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
				((HttpsURLConnection) urlConnection).setSSLSocketFactory(sslSocketFactory);
			}
			if (deactivateHostnameVerification) {
				((HttpsURLConnection) urlConnection).setHostnameVerifier(TRUSTALLHOSTNAMES_HOSTNAMEVERIFIER);
			}
		}

		if (httpRequest.getConnectTimeoutMillis() >= 0) {
			urlConnection.setConnectTimeout(httpRequest.getConnectTimeoutMillis());
		}

		if (httpRequest.getReadTimeoutMillis() >= 0) {
			urlConnection.setReadTimeout(httpRequest.getReadTimeoutMillis());
		}

		if (httpRequest.getHeaders() != null && httpRequest.getHeaders().size() > 0) {
			if (debugLog) {
				System.out.println("Request Headers: ");
			}

			for (final Entry<String, String> headerEntry : httpRequest.getHeaders().entrySet()) {
				urlConnection.setRequestProperty(headerEntry.getKey(), headerEntry.getValue());

				if (debugLog) {
					System.out.println(headerEntry.getKey() + ": " + headerEntry.getValue());
				}
			}
		}

		final String cookieHeaderValue = createCookieHeaderValue(httpRequest);
		if (cookieHeaderValue != null) {
			urlConnection.setRequestProperty(HttpConstants.HTTPHEADERNAME_COOKIE, cookieHeaderValue);
		}

		if (httpRequest.getRequestBodyContentStream() != null) {
			urlConnection.setDoOutput(true);
			try (OutputStream outputStream = urlConnection.getOutputStream()) {
				NetworkUtilities.copy(httpRequest.getRequestBodyContentStream(), outputStream);
				outputStream.flush();
			}
		} else if (httpRequest.getRequestBody() != null) {
			urlConnection.setDoOutput(true);

			final String httpRequestBody = httpRequest.getRequestBody();
			final Charset encoding = httpRequest.getEncoding() == null ? StandardCharsets.UTF_8
					: httpRequest.getEncoding();
			final byte[] httpRequestBodyData = httpRequestBody.getBytes(encoding);

			if (!hasRequestHeader(httpRequest, HttpConstants.HTTPHEADERNAME_CONTENTTYPE)) {
				urlConnection.setRequestProperty(HttpConstants.HTTPHEADERNAME_CONTENTTYPE,
						"text/plain; charset=" + encoding);
			}

			urlConnection.setRequestProperty(HttpConstants.HTTPHEADERNAME_CONTENTLENGTH,
					Integer.toString(httpRequestBodyData.length));
			try (OutputStream outputStream = urlConnection.getOutputStream()) {
				outputStream.write(httpRequestBodyData);
				outputStream.flush();
			}
		} else if (httpRequest.getUploadFileAttachments() != null
				&& httpRequest.getUploadFileAttachments().size() > 0) {
			final String boundary = HttpUtilities.generateBoundary();
			urlConnection.setDoOutput(true);
			urlConnection.setRequestProperty(HttpConstants.HTTPHEADERNAME_CONTENTTYPE,
					HttpContentType.MultipartForm.getStringRepresentation() + "; boundary=" + boundary);

			try (OutputStream outputStream = urlConnection.getOutputStream()) {
				writeMultipartBody(httpRequest, boundary, outputStream);
				outputStream.flush();
			}
		} else if (httpRequest.getPostParameters() != null && httpRequest.getPostParameters().size() > 0) {
			urlConnection.setDoOutput(true);

			if (!hasRequestHeader(httpRequest, HttpConstants.HTTPHEADERNAME_CONTENTTYPE)) {
				urlConnection.setRequestProperty(HttpConstants.HTTPHEADERNAME_CONTENTTYPE,
						HttpContentType.HtmlForm.getStringRepresentation());
			}

			final String httpRequestBody = convertToParameterString(httpRequest.getPostParameters(), null);

			if (debugLog) {
				System.out.println("Request Body: ");
				System.out.println(httpRequestBody);
			}

			final Charset encoding = httpRequest.getEncoding() == null ? StandardCharsets.UTF_8
					: httpRequest.getEncoding();
			final byte[] httpRequestBodyData = httpRequestBody.getBytes(encoding);

			urlConnection.setRequestProperty(HttpConstants.HTTPHEADERNAME_CONTENTLENGTH,
					Integer.toString(httpRequestBodyData.length));
			try (OutputStream outputStream = urlConnection.getOutputStream()) {
				outputStream.write(httpRequestBodyData);
				outputStream.flush();
			}
		}

		urlConnection.connect();

		return new HttpUrlConnectionResponse(urlConnection);
	}

	/**
	 * Request header names that java.net.http.HttpClient manages itself (it throws an
	 * IllegalArgumentException if they are set) or that are forbidden in HTTP/2 (connection specific
	 * headers, RFC 9113 8.2.2). Such headers from the request are skipped for HTTP/2.
	 */
	private static final Set<String> HTTP2_SKIPPED_REQUEST_HEADERS = Set.of("connection", "content-length", "expect", "host",
			"upgrade", "keep-alive", "proxy-connection", "transfer-encoding");

	/**
	 * Sends a request via {@link HttpClient} with HTTP/2 without following redirects.
	 * <p>
	 * For "https" the protocol is negotiated via TLS ALPN, for "http" the JDK tries an "h2c" upgrade.
	 * If the server does not support HTTP/2, the JDK falls back to HTTP/1.1 transparently.
	 * </p>
	 */
	private static ReceivedResponse sendWithHttpClient(final HttpRequest httpRequest, final String requestedUrl,
			final Proxy proxy, final String proxyUsername, final String proxyPassword, final TrustManager trustManager,
			final boolean deactivateHostnameVerification) throws Exception {
		final URI requestUri = URI.create(requestedUrl);

		final HttpClient.Builder httpClientBuilder = HttpClient.newBuilder()
				.version(HttpClient.Version.HTTP_2)
				// Redirects are handled by executeHttpRequest, so that credentials are not forwarded to other origins
				.followRedirects(HttpClient.Redirect.NEVER);

		// Same semantics as for HttpURLConnection above: null means a direct connection
		if (proxy == null || proxy.type() == Proxy.Type.DIRECT) {
			httpClientBuilder.proxy(HttpClient.Builder.NO_PROXY);
		} else if (proxy.type() == Proxy.Type.HTTP && proxy.address() instanceof final InetSocketAddress proxyAddress) {
			httpClientBuilder.proxy(ProxySelector.of(proxyAddress));
		} else {
			throw new Exception("Proxy type '" + proxy.type() + "' is not supported for HTTP/2 requests");
		}

		if (requestedUrl.toLowerCase(Locale.ROOT).startsWith(HttpConstants.SECURE_HTTP_PROTOCOL_SIGN)
				&& (trustManager != null || deactivateHostnameVerification)) {
			// HttpClient has no HostnameVerifier. Its hostname check is done by the TrustManager (endpoint
			// identification), so for a deactivated hostname verification the TrustManager is wrapped.
			final TrustManager effectiveTrustManager = deactivateHostnameVerification
					? createTrustManagerWithoutHostnameVerification(trustManager)
					: trustManager;
			final SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
			sslContext.init(null, new TrustManager[] { effectiveTrustManager }, new SecureRandom());
			httpClientBuilder.sslContext(sslContext);
		}

		if (httpRequest.getConnectTimeoutMillis() > 0) {
			httpClientBuilder.connectTimeout(Duration.ofMillis(httpRequest.getConnectTimeoutMillis()));
		}

		final java.net.http.HttpRequest.Builder requestBuilder = java.net.http.HttpRequest.newBuilder(requestUri);

		if (httpRequest.getReadTimeoutMillis() > 0) {
			// HttpClient has no read timeout between data packets. This timeout applies until the response headers are received.
			requestBuilder.timeout(Duration.ofMillis(httpRequest.getReadTimeoutMillis()));
		}

		if (proxy != null && proxy.type() == Proxy.Type.HTTP && proxyUsername != null && proxyPassword != null) {
			// For "https" via proxy this header is only used for the CONNECT request, not forwarded to the target server.
			// NOTE: The JDK refuses Basic authentication for tunneling by default, see system property "jdk.http.auth.tunneling.disabledSchemes".
			requestBuilder.setHeader(HttpConstants.HTTPHEADERNAME_PROXY_AUTHORIZATION,
					createProxyAuthorizationHeaderValue(proxyUsername, proxyPassword));
		}

		if (httpRequest.getHeaders() != null && httpRequest.getHeaders().size() > 0) {
			if (debugLog) {
				System.out.println("Request Headers: ");
			}

			for (final Entry<String, String> headerEntry : httpRequest.getHeaders().entrySet()) {
				if (HTTP2_SKIPPED_REQUEST_HEADERS.contains(headerEntry.getKey().toLowerCase(Locale.ROOT))) {
					if (debugLog) {
						System.out.println("(skipped for HTTP/2) " + headerEntry.getKey() + ": " + headerEntry.getValue());
					}
					continue;
				}

				requestBuilder.setHeader(headerEntry.getKey(), headerEntry.getValue());

				if (debugLog) {
					System.out.println(headerEntry.getKey() + ": " + headerEntry.getValue());
				}
			}
		}

		final String cookieHeaderValue = createCookieHeaderValue(httpRequest);
		if (cookieHeaderValue != null) {
			requestBuilder.setHeader(HttpConstants.HTTPHEADERNAME_COOKIE, cookieHeaderValue);
		}

		// Content-Length is set by HttpClient itself from the BodyPublisher
		final java.net.http.HttpRequest.BodyPublisher bodyPublisher;
		if (httpRequest.getRequestBodyContentStream() != null) {
			final InputStream requestBodyContentStream = httpRequest.getRequestBodyContentStream();
			bodyPublisher = java.net.http.HttpRequest.BodyPublishers.ofInputStream(() -> requestBodyContentStream);
		} else if (httpRequest.getRequestBody() != null) {
			final Charset encoding = httpRequest.getEncoding() == null ? StandardCharsets.UTF_8
					: httpRequest.getEncoding();
			if (!hasRequestHeader(httpRequest, HttpConstants.HTTPHEADERNAME_CONTENTTYPE)) {
				requestBuilder.setHeader(HttpConstants.HTTPHEADERNAME_CONTENTTYPE, "text/plain; charset=" + encoding);
			}
			bodyPublisher = java.net.http.HttpRequest.BodyPublishers.ofByteArray(httpRequest.getRequestBody().getBytes(encoding));
		} else if (httpRequest.getUploadFileAttachments() != null
				&& httpRequest.getUploadFileAttachments().size() > 0) {
			final String boundary = HttpUtilities.generateBoundary();
			requestBuilder.setHeader(HttpConstants.HTTPHEADERNAME_CONTENTTYPE,
					HttpContentType.MultipartForm.getStringRepresentation() + "; boundary=" + boundary);
			final ByteArrayOutputStream multipartBodyStream = new ByteArrayOutputStream();
			writeMultipartBody(httpRequest, boundary, multipartBodyStream);
			bodyPublisher = java.net.http.HttpRequest.BodyPublishers.ofByteArray(multipartBodyStream.toByteArray());
		} else if (httpRequest.getPostParameters() != null && httpRequest.getPostParameters().size() > 0) {
			if (!hasRequestHeader(httpRequest, HttpConstants.HTTPHEADERNAME_CONTENTTYPE)) {
				requestBuilder.setHeader(HttpConstants.HTTPHEADERNAME_CONTENTTYPE,
						HttpContentType.HtmlForm.getStringRepresentation());
			}

			final String httpRequestBody = convertToParameterString(httpRequest.getPostParameters(), null);

			if (debugLog) {
				System.out.println("Request Body: ");
				System.out.println(httpRequestBody);
			}

			final Charset encoding = httpRequest.getEncoding() == null ? StandardCharsets.UTF_8
					: httpRequest.getEncoding();
			bodyPublisher = java.net.http.HttpRequest.BodyPublishers.ofByteArray(httpRequestBody.getBytes(encoding));
		} else {
			bodyPublisher = null;
		}

		String requestMethod = httpRequest.getRequestMethod() == null ? HttpMethod.GET.name() : httpRequest.getRequestMethod().name();
		if (bodyPublisher != null && HttpMethod.GET.name().equals(requestMethod)) {
			// Same behaviour as HttpURLConnection, which silently turns a GET request with a body into a POST request
			requestMethod = HttpMethod.POST.name();
		}
		requestBuilder.method(requestMethod,
				bodyPublisher == null ? java.net.http.HttpRequest.BodyPublishers.noBody() : bodyPublisher);

		final HttpClient httpClient = httpClientBuilder.build();
		try {
			final java.net.http.HttpResponse<InputStream> response = httpClient.send(requestBuilder.build(),
					java.net.http.HttpResponse.BodyHandlers.ofInputStream());
			if (debugLog) {
				System.out.println("Used HTTP version: " + response.version());
			}
			return new HttpClientResponse(httpClient, response);
		} catch (final Exception e) {
			closeHttpClient(httpClient);
			throw e;
		}
	}

	/**
	 * Writes the multipart form data (post parameters and file attachments) of a request.
	 */
	private static void writeMultipartBody(final HttpRequest httpRequest, final String boundary, final OutputStream outputStream) throws IOException {
		if (httpRequest.getPostParameters() != null && httpRequest.getPostParameters().size() > 0) {
			for (final Entry<String, List<Object>> entry : httpRequest.getPostParameters().entrySet()) {
				for (final Object value : entry.getValue()) {
					outputStream.write(("--" + boundary + "\r\n").getBytes(StandardCharsets.UTF_8));
					outputStream.write((HttpConstants.HTTPHEADERNAME_DISPOSITION + ": form-data; name=\""
							+ urlEncode(entry.getKey(), StandardCharsets.UTF_8) + "\"\r\n")
									.getBytes(StandardCharsets.UTF_8));
					outputStream.write("\r\n".getBytes(StandardCharsets.UTF_8));
					if (value != null) {
						outputStream.write(value.toString().getBytes(StandardCharsets.UTF_8));
					}
					outputStream.write("\r\n".getBytes(StandardCharsets.UTF_8));
				}
			}
		}

		for (final UploadFileAttachment uploadFileAttachment : httpRequest.getUploadFileAttachments()) {
			outputStream.write(("--" + boundary + "\r\n").getBytes(StandardCharsets.UTF_8));
			// htmlInputName/fileName must be sanitized before being embedded in the Content-Disposition
			// header: unlike the postParameters branch above (which URL-encodes the field name), these
			// were previously written verbatim, so a name or filename containing '"' or CR/LF could
			// break out of the header value and inject additional (attacker-controlled) header lines
			// or multipart parts.
			outputStream.write((HttpConstants.HTTPHEADERNAME_DISPOSITION + ": form-data; name=\""
					+ escapeMultipartHeaderValue(uploadFileAttachment.getHtmlInputName()) + "\"; filename=\""
					+ escapeMultipartHeaderValue(uploadFileAttachment.getFileName()) + "\"\r\n").getBytes(StandardCharsets.UTF_8));
			outputStream.write("\r\n".getBytes(StandardCharsets.UTF_8));

			outputStream.write(uploadFileAttachment.getData());

			outputStream.write("\r\n".getBytes(StandardCharsets.UTF_8));
		}

		outputStream.write(("--" + boundary + "--" + "\r\n").getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * True if the request defines a header with the given name (case insensitive).
	 */
	private static boolean hasRequestHeader(final HttpRequest httpRequest, final String headerName) {
		if (httpRequest.getHeaders() != null) {
			for (final String requestHeaderName : httpRequest.getHeaders().keySet()) {
				if (headerName.equalsIgnoreCase(requestHeaderName)) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Creates the value of the "Cookie" request header, or null if the request has no cookies.
	 */
	private static String createCookieHeaderValue(final HttpRequest httpRequest) {
		if (httpRequest.getCookieData() == null || httpRequest.getCookieData().size() == 0) {
			return null;
		}
		final StringBuilder cookieValue = new StringBuilder();
		for (final Entry<String, String> cookieEntry : httpRequest.getCookieData().entrySet()) {
			if (cookieValue.length() > 0) {
				cookieValue.append("; ");
			}
			cookieValue.append(
					encodeForCookie(cookieEntry.getKey()) + "=" + encodeForCookie(cookieEntry.getValue()));
		}
		return cookieValue.toString();
	}

	private static String createProxyAuthorizationHeaderValue(final String proxyUsername, final String proxyPassword) {
		final String proxyCredentials = proxyUsername + ":" + proxyPassword;
		return HttpConstants.AUTHORIZATIONHEADER_START_BASIC + " "
				+ Base64.getEncoder().encodeToString(proxyCredentials.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Wraps a TrustManager (null for the system's default truststore), so that the certificate chain is
	 * still checked, but not the host name. Needed for HttpClient, which has no HostnameVerifier.
	 * <p>
	 * The wrapper must be a {@link X509ExtendedTrustManager}: a plain {@link X509TrustManager} would be
	 * wrapped by JSSE, which then checks the host name again.
	 * </p>
	 */
	private static X509ExtendedTrustManager createTrustManagerWithoutHostnameVerification(final TrustManager trustManager) throws Exception {
		final X509TrustManager delegateTrustManager;
		if (trustManager == null) {
			final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			trustManagerFactory.init((KeyStore) null);
			X509TrustManager defaultTrustManager = null;
			for (final TrustManager defaultTrustManagerCandidate : trustManagerFactory.getTrustManagers()) {
				if (defaultTrustManagerCandidate instanceof final X509TrustManager x509TrustManager) {
					defaultTrustManager = x509TrustManager;
					break;
				}
			}
			if (defaultTrustManager == null) {
				throw new Exception("No default X509TrustManager available");
			}
			delegateTrustManager = defaultTrustManager;
		} else if (trustManager instanceof final X509TrustManager x509TrustManager) {
			delegateTrustManager = x509TrustManager;
		} else {
			throw new Exception("Unsupported TrustManager type '" + trustManager.getClass().getName() + "', X509TrustManager expected");
		}

		// The variants with Socket/SSLEngine are the ones doing the endpoint identification (host name check).
		// They are redirected to the variants without, which only check the certificate chain.
		return new X509ExtendedTrustManager() {
			@Override
			public void checkClientTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
				delegateTrustManager.checkClientTrusted(chain, authType);
			}

			@Override
			public void checkServerTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
				delegateTrustManager.checkServerTrusted(chain, authType);
			}

			@Override
			public void checkClientTrusted(final X509Certificate[] chain, final String authType, final Socket socket) throws CertificateException {
				delegateTrustManager.checkClientTrusted(chain, authType);
			}

			@Override
			public void checkServerTrusted(final X509Certificate[] chain, final String authType, final Socket socket) throws CertificateException {
				delegateTrustManager.checkServerTrusted(chain, authType);
			}

			@Override
			public void checkClientTrusted(final X509Certificate[] chain, final String authType, final SSLEngine engine) throws CertificateException {
				delegateTrustManager.checkClientTrusted(chain, authType);
			}

			@Override
			public void checkServerTrusted(final X509Certificate[] chain, final String authType, final SSLEngine engine) throws CertificateException {
				delegateTrustManager.checkServerTrusted(chain, authType);
			}

			@Override
			public X509Certificate[] getAcceptedIssuers() {
				return delegateTrustManager.getAcceptedIssuers();
			}
		};
	}

	/**
	 * HttpClient only implements AutoCloseable since Java 21. On older Java versions its resources are
	 * released as soon as it is no longer referenced.
	 */
	private static void closeHttpClient(final HttpClient httpClient) {
		if (httpClient instanceof final AutoCloseable closeableHttpClient) {
			try {
				closeableHttpClient.close();
			} catch (@SuppressWarnings("unused") final Exception e) {
				// Do nothing
			}
		}
	}

	/**
	 * Transport independent access to a received response.
	 */
	private interface ReceivedResponse extends AutoCloseable {
		int getStatusCode() throws IOException;

		String getStatusMessage() throws IOException;

		/**
		 * All response headers, multiple values per name possible. Keys may be null or HTTP/2 pseudo headers.
		 */
		Map<String, List<String>> getHeaderFields();

		/**
		 * The response body, for status codes &gt;= 400 the error body. May be null.
		 */
		InputStream getBodyStream() throws IOException;

		String getContentType();

		String getIpAddress();

		/**
		 * The HTTP version actually used for the response, e.g. after a fallback from HTTP/2 to HTTP/1.1.
		 */
		HttpVersion getHttpVersion();

		@Override
		void close();
	}

	private static final class HttpUrlConnectionResponse implements ReceivedResponse {
		private final HttpURLConnection urlConnection;

		private HttpUrlConnectionResponse(final HttpURLConnection urlConnection) {
			this.urlConnection = urlConnection;
		}

		@Override
		public int getStatusCode() throws IOException {
			return urlConnection.getResponseCode();
		}

		@Override
		public String getStatusMessage() throws IOException {
			return urlConnection.getResponseMessage();
		}

		@Override
		public Map<String, List<String>> getHeaderFields() {
			return urlConnection.getHeaderFields();
		}

		@Override
		public InputStream getBodyStream() throws IOException {
			if (urlConnection.getResponseCode() < HttpURLConnection.HTTP_BAD_REQUEST) {
				return urlConnection.getInputStream();
			} else {
				return urlConnection.getErrorStream();
			}
		}

		@Override
		public String getContentType() {
			return urlConnection.getContentType();
		}

		@Override
		public String getIpAddress() {
			return HttpUtilities.getIpAddress(urlConnection);
		}

		@Override
		public HttpVersion getHttpVersion() {
			// HttpURLConnection always sends HTTP/1.1, but an old server may answer with HTTP/1.0.
			// The status line (e.g. "HTTP/1.0 200 OK") is exposed as header field 0.
			final String statusLine = urlConnection.getHeaderField(0);
			if (statusLine != null && statusLine.trim().toUpperCase(Locale.ROOT).startsWith("HTTP/1.0")) {
				return HttpVersion.HTTP_1_0;
			} else {
				return HttpVersion.HTTP_1_1;
			}
		}

		@Override
		public void close() {
			// Nothing to do: the connection is kept for reuse (keep-alive) by HttpURLConnection
		}
	}

	private static final class HttpClientResponse implements ReceivedResponse {
		private final HttpClient httpClient;
		private final java.net.http.HttpResponse<InputStream> response;

		private HttpClientResponse(final HttpClient httpClient, final java.net.http.HttpResponse<InputStream> response) {
			this.httpClient = httpClient;
			this.response = response;
		}

		@Override
		public int getStatusCode() {
			return response.statusCode();
		}

		@Override
		public String getStatusMessage() {
			// HTTP/2 has no reason phrase, so the standard text is used
			return getHttpStatusText(response.statusCode());
		}

		@Override
		public Map<String, List<String>> getHeaderFields() {
			return response.headers().map();
		}

		@Override
		public InputStream getBodyStream() {
			return response.body();
		}

		@Override
		public String getContentType() {
			return response.headers().firstValue(HttpConstants.HTTPHEADERNAME_CONTENTTYPE).orElse(null);
		}

		@Override
		public String getIpAddress() {
			return HttpUtilities.getIpAddress(response.headers().firstValue("X-Real-IP").orElse(null),
					response.headers().firstValue("X-Forwarded-For").orElse(null), response.uri().getHost());
		}

		@Override
		public HttpVersion getHttpVersion() {
			// HTTP_1_1 if the server did not support HTTP/2 and HttpClient fell back
			return response.version() == HttpClient.Version.HTTP_2 ? HttpVersion.HTTP_2 : HttpVersion.HTTP_1_1;
		}

		@Override
		public void close() {
			// Closing the body stream also cancels an unread HTTP/2 stream (e.g. for redirects)
			try {
				if (response.body() != null) {
					response.body().close();
				}
			} catch (@SuppressWarnings("unused") final IOException e) {
				// Do nothing
			}
			closeHttpClient(httpClient);
		}
	}

	/**
	 * Converts parameters to URL encoded form data like "a=1&amp;b=2".
	 *
	 * @param parameters
	 *            the parameters, each name with its values
	 * @param encoding
	 *            the encoding, null for UTF-8
	 * @return the parameter string, or null if the parameters are null
	 */
	public static String convertToParameterString(final Map<String, List<Object>> parameters, Charset encoding) {
		if (parameters == null) {
			return null;
		} else {
			if (encoding == null) {
				encoding = StandardCharsets.UTF_8;
			}
			final StringBuilder returnValue = new StringBuilder();
			for (final Entry<String, List<Object>> entry : parameters.entrySet()) {
				for (final Object value : entry.getValue()) {
					if (returnValue.length() > 0) {
						returnValue.append("&");
					}
					returnValue.append(urlEncode(entry.getKey(), encoding));
					returnValue.append("=");
					if (value != null) {
						returnValue.append(urlEncode(value.toString(), encoding));
					}
				}
			}

			return returnValue.toString();
		}
	}

	/**
	 * URL encodes a text for form data (blanks become "+").
	 *
	 * @param data
	 *            the text
	 * @param charset
	 *            the encoding
	 * @return the encoded text
	 */
	public static String urlEncode(final String data, final Charset charset) {
		return URLEncoder.encode(data, charset);
	}

	/**
	 * Decodes URL encoded form data ("+" becomes a blank).
	 *
	 * @param data
	 *            the encoded text
	 * @param charset
	 *            the encoding
	 * @return the decoded text
	 * @throws IllegalArgumentException
	 *             if the text contains invalid escapes
	 */
	public static String urlDecode(final String data, final Charset charset) {
		return URLDecoder.decode(data, charset);
	}

	/**
	 * Sends a POST request without waiting for the answer, e.g. to trigger a server side action. TLS
	 * certificates and host names are not checked (insecure), so only use it for data that needs no
	 * protection.
	 *
	 * @param pingUrl
	 *            the URL
	 * @param proxy
	 *            the proxy, null for a direct connection
	 * @throws IOException
	 *             if the connection fails
	 * @throws NoSuchAlgorithmException
	 *             if TLS is not available
	 * @throws KeyManagementException
	 *             if the TLS context cannot be initialized
	 */
	public static void pingUrlWithoutSslCheckNoWaitForAnswer(final String pingUrl, final Proxy proxy)
			throws IOException, NoSuchAlgorithmException, KeyManagementException {
		InputStream downloadStream = null;
		try {
			if (pingUrl.startsWith("https")) {
				// Deactivate SSL-Certificates check
				final SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
				final TrustManager[] tms = new TrustManager[] { new X509TrustManager() {
					@Override
					public X509Certificate[] getAcceptedIssuers() {
						// X509TrustManager contract requires a non-null array
						return new X509Certificate[0];
					}

					@Override
					public void checkServerTrusted(final X509Certificate[] arg0, final String arg1)
							throws CertificateException {
						// nothing to do
					}

					@Override
					public void checkClientTrusted(final X509Certificate[] arg0, final String arg1)
							throws CertificateException {
						// nothing to do
					}
				} };
				sslContext.init(null, tms, null);
				final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
				final HttpsURLConnection urlConnection = (HttpsURLConnection) URI.create(pingUrl).toURL()
						.openConnection(proxy == null ? Proxy.NO_PROXY : proxy);
				urlConnection.setSSLSocketFactory(sslSocketFactory);
				urlConnection.setHostnameVerifier(TRUSTALLHOSTNAMES_HOSTNAMEVERIFIER);
				urlConnection.setRequestMethod("POST");
				urlConnection.setConnectTimeout(5000);
				urlConnection.setReadTimeout(100);
				urlConnection.setDoInput(true);
				urlConnection.setDoOutput(false);
				downloadStream = urlConnection.getInputStream();
			} else {
				final HttpURLConnection urlConnection = (HttpURLConnection) URI.create(pingUrl).toURL()
						.openConnection(proxy == null ? Proxy.NO_PROXY : proxy);
				urlConnection.setRequestMethod("POST");
				urlConnection.setConnectTimeout(5000);
				urlConnection.setReadTimeout(100);
				urlConnection.setDoInput(true);
				urlConnection.setDoOutput(false);
				downloadStream = urlConnection.getInputStream();
			}
		} catch (@SuppressWarnings("unused") final SocketTimeoutException stex) {
			// This Exception is expected for the real short timeout
		} finally {
			if (downloadStream != null) {
				try {
					downloadStream.close();
				} catch (@SuppressWarnings("unused") final IOException e) {
					// Do nothing
				}
			}
		}
	}

	/**
	 * Creates a "Content-Type" header for URL encoded form data.
	 *
	 * @param encoding
	 *            the encoding to state as charset, null for none
	 * @return the header with its value
	 */
	public static Map<String, List<String>> createHtmlFormMimetypeHeader(final Charset encoding) {
		final Map<String, List<String>> returnMap = new HashMap<>();
		final List<String> valueList = new ArrayList<>();
		if (encoding == null) {
			valueList.add(HttpContentType.HtmlForm.getStringRepresentation());
		} else {
			valueList.add(
					HttpContentType.HtmlForm.getStringRepresentation() + "; charset=" + encoding.name().toLowerCase(Locale.ROOT));
		}
		returnMap.put(HttpConstants.HTTPHEADERNAME_CONTENTTYPE, valueList);
		return returnMap;
	}

	/**
	 * Adds a query parameter to an URL, before a fragment.
	 *
	 * @param url
	 *            the URL
	 * @param parameterName
	 *            the parameter name
	 * @param parameterValue
	 *            the value; arrays are joined with ","
	 * @param encodingCharSet
	 *            the encoding for URL encoding of name and value, null for no encoding
	 * @return the new URL
	 */
	public static String addUrlParameter(final String url, final String parameterName, final Object parameterValue,
			final Charset encodingCharSet) {
		final StringBuilder escapedParameterNameAndValue = new StringBuilder();

		if (encodingCharSet == null) {
			escapedParameterNameAndValue.append(parameterName);
		} else {
			escapedParameterNameAndValue.append(urlEncode(parameterName, encodingCharSet));
		}

		escapedParameterNameAndValue.append('=');

		if (parameterValue instanceof char[]) {
			if (encodingCharSet == null) {
				escapedParameterNameAndValue.append(new String((char[]) parameterValue));
			} else {
				escapedParameterNameAndValue.append(urlEncode(new String((char[]) parameterValue), encodingCharSet));
			}
		} else if (parameterValue instanceof Object[]) {
			boolean isFirstValue = true;
			for (final Object value : (Object[]) parameterValue) {
				if (!isFirstValue) {
					escapedParameterNameAndValue.append(",");
				}
				if (encodingCharSet == null) {
					escapedParameterNameAndValue.append(String.valueOf(value));
				} else {
					escapedParameterNameAndValue.append(urlEncode(String.valueOf(value), encodingCharSet));
				}
				isFirstValue = false;
			}
		} else {
			if (encodingCharSet == null) {
				escapedParameterNameAndValue.append(String.valueOf(parameterValue));
			} else {
				escapedParameterNameAndValue.append(urlEncode(String.valueOf(parameterValue), encodingCharSet));
			}
		}
		return addUrlParameter(url, escapedParameterNameAndValue.toString());
	}

	/**
	 * Adds an already encoded query parameter to an URL, before a fragment.
	 *
	 * @param url
	 *            the URL
	 * @param escapedParameterNameAndValue
	 *            the encoded parameter, e.g. "a=1"
	 * @return the new URL
	 */
	public static String addUrlParameter(final String url, final String escapedParameterNameAndValue) {
		final StringBuilder newUrl = new StringBuilder();
		final int insertPosition = url.indexOf('#');

		if (insertPosition < 0) {
			newUrl.append(url);
			newUrl.append(url.indexOf('?') <= -1 ? '?' : '&');
			newUrl.append(escapedParameterNameAndValue);
		} else {
			newUrl.append(url.substring(0, insertPosition));
			// Only a '?' before the fragment starts a query, a '?' within the fragment does not
			newUrl.append(url.substring(0, insertPosition).indexOf('?') <= -1 ? '?' : '&');
			newUrl.append(escapedParameterNameAndValue);
			newUrl.append(url.substring(insertPosition));
		}

		return newUrl.toString();
	}

	/**
	 * Adds an already encoded matrix parameter (";name=value") to the path of an URL.
	 *
	 * @param url
	 *            the URL
	 * @param escapedParameterNameAndValue
	 *            the encoded parameter, e.g. "a=1"
	 * @return the new URL
	 */
	public static String addPathParameter(final String url, final String escapedParameterNameAndValue) {
		final StringBuilder newUrl = new StringBuilder();
		int insertPosition = url.indexOf('?');
		if (insertPosition < 0) {
			insertPosition = url.indexOf('#');
		}

		if (insertPosition < 0) {
			newUrl.append(url);
			newUrl.append(";");
			newUrl.append(escapedParameterNameAndValue);
		} else {
			newUrl.append(url.substring(0, insertPosition));
			newUrl.append(";");
			newUrl.append(escapedParameterNameAndValue);
			newUrl.append(url.substring(insertPosition));
		}

		return newUrl.toString();
	}

	/**
	 * Finds an unquoted parameter like "name=value" in HTML text. The value consists of word
	 * characters only.
	 *
	 * @param htmlText
	 *            the HTML text
	 * @param parameterName
	 *            the parameter name
	 * @return the value, or null if not found
	 */
	public static String getPlainParameterFromHtml(final String htmlText, final String parameterName) {
		if (NetworkUtilities.isBlank(htmlText)) {
			return null;
		} else {
			// The parameter name is quoted, so regex characters in it are matched literally
			final Pattern parameterPattern = Pattern.compile("\\W" + Pattern.quote(parameterName) + "\\s*=(\\w*)\\W",
					Pattern.MULTILINE);
			final Matcher parameterMatcher = parameterPattern.matcher(htmlText);
			if (parameterMatcher.find()) {
				return parameterMatcher.group(1).trim();
			} else {
				return null;
			}
		}
	}

	/**
	 * Finds a quoted parameter like name="value" in HTML text. The value consists of word characters
	 * only.
	 *
	 * @param htmlText
	 *            the HTML text
	 * @param parameterName
	 *            the parameter name
	 * @return the value, or null if not found
	 */
	public static String getQuotedParameterFromHtml(final String htmlText, final String parameterName) {
		if (NetworkUtilities.isBlank(htmlText)) {
			return null;
		} else {
			// The parameter name is quoted, so regex characters in it are matched literally
			final Pattern parameterPattern = Pattern.compile("\\W" + Pattern.quote(parameterName) + "\\s*=\\s*\"(\\w*)\"\\W",
					Pattern.MULTILINE);
			final Matcher parameterMatcher = parameterPattern.matcher(htmlText);
			if (parameterMatcher.find()) {
				return parameterMatcher.group(1).trim();
			} else {
				return null;
			}
		}
	}

	/**
	 * Returns the standard text of an HTTP status code.
	 *
	 * @param httpStatusCode
	 *            the status code
	 * @return the text, e.g. "Not Found"
	 */
	public static String getHttpStatusText(final int httpStatusCode) {
		switch (httpStatusCode) {
			case HttpURLConnection.HTTP_OK:
				// 200
				return "OK";
			case HttpURLConnection.HTTP_CREATED:
				// 201
				return "Created";
			case HttpURLConnection.HTTP_ACCEPTED:
				// 202
				return "Accepted";
			case HttpURLConnection.HTTP_NOT_AUTHORITATIVE:
				// 203
				return "Non-Authoritative Information";
			case HttpURLConnection.HTTP_NO_CONTENT:
				// 204
				return "No Content";
			case HttpURLConnection.HTTP_RESET:
				// 205
				return "Reset Content";
			case HttpURLConnection.HTTP_PARTIAL:
				// 206
				return "Partial Content";
			case HttpURLConnection.HTTP_MULT_CHOICE:
				// 300
				return "Multiple Choices";
			case HttpURLConnection.HTTP_MOVED_PERM:
				// 301
				return "Moved Permanently";
			case HttpURLConnection.HTTP_MOVED_TEMP:
				// 302
				return "Found";
			case HttpURLConnection.HTTP_SEE_OTHER:
				// 303
				return "See Other";
			case HttpURLConnection.HTTP_NOT_MODIFIED:
				// 304
				return "Not Modified";
			case HttpURLConnection.HTTP_USE_PROXY:
				// 305
				return "Use Proxy";
			case HTTP_TEMPORARY_REDIRECT:
				// 307
				return "Temporary Redirect";
			case HTTP_PERMANENT_REDIRECT:
				// 308
				return "Permanent Redirect";
			case HttpURLConnection.HTTP_BAD_REQUEST:
				// 400
				return "Bad Request";
			case HttpURLConnection.HTTP_UNAUTHORIZED:
				// 401
				return "Unauthorized";
			case HttpURLConnection.HTTP_PAYMENT_REQUIRED:
				// 402
				return "Payment Required";
			case HttpURLConnection.HTTP_FORBIDDEN:
				// 403
				return "Forbidden";
			case HttpURLConnection.HTTP_NOT_FOUND:
				// 404
				return "Not Found";
			case HttpURLConnection.HTTP_BAD_METHOD:
				// 405
				return "Method Not Allowed";
			case HttpURLConnection.HTTP_NOT_ACCEPTABLE:
				// 406
				return "Not Acceptable";
			case HttpURLConnection.HTTP_PROXY_AUTH:
				// 407
				return "Proxy Authentication Required";
			case HttpURLConnection.HTTP_CLIENT_TIMEOUT:
				// 408
				return "Request Time-Out";
			case HttpURLConnection.HTTP_CONFLICT:
				// 409
				return "Conflict";
			case HttpURLConnection.HTTP_GONE:
				// 410
				return "Gone";
			case HttpURLConnection.HTTP_LENGTH_REQUIRED:
				// 411
				return "Length Required";
			case HttpURLConnection.HTTP_PRECON_FAILED:
				// 412
				return "Precondition Failed";
			case HttpURLConnection.HTTP_ENTITY_TOO_LARGE:
				// 413
				return "Request Entity Too Large";
			case HttpURLConnection.HTTP_REQ_TOO_LONG:
				// 414
				return "Request-URI Too Large";
			case HttpURLConnection.HTTP_UNSUPPORTED_TYPE:
				// 415
				return "Unsupported Media Type";
			case HttpURLConnection.HTTP_INTERNAL_ERROR:
				// 500
				return "Internal Server Error";
			case HttpURLConnection.HTTP_NOT_IMPLEMENTED:
				// 501
				return "Not Implemented";
			case HttpURLConnection.HTTP_BAD_GATEWAY:
				// 502
				return "Bad Gateway";
			case HttpURLConnection.HTTP_UNAVAILABLE:
				// 503
				return "Service Unavailable";
			case HttpURLConnection.HTTP_GATEWAY_TIMEOUT:
				// 504
				return "Gateway Timeout";
			case HttpURLConnection.HTTP_VERSION:
				// 505
				return "HTTP Version Not Supported";
			default:
				return "Unknown Http Status Code (" + httpStatusCode + ")";
		}
	}

	/**
	 * Creates the value of an "Authorization" header for basic authentication.
	 *
	 * @param username
	 *            the user name
	 * @param password
	 *            the password
	 * @return the header value, e.g. "Basic dXNlcjpwYXNz"
	 */
	public static String createBasicAuthenticationHeaderValue(final String username, final String password) {
		return "Basic "
				+ Base64.getEncoder().encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Sanitizes a value that is embedded in a quoted multipart Content-Disposition header parameter
	 * (name="..." / filename="..."). Strips CR and LF (which would otherwise allow injecting additional
	 * header lines or multipart boundaries/parts) and escapes backslashes and double quotes per RFC 7578 §4.2.
	 */
	private static String escapeMultipartHeaderValue(final String value) {
		if (value == null) {
			return "";
		}
		return value.replace("\r", "").replace("\n", "")
				.replace("\\", "\\\\")
				.replace("\"", "\\\"");
	}

	private static final Pattern CONTENT_DISPOSITION_FILENAME_EXTENDED_PATTERN =
			Pattern.compile("filename\\*\\s*=\\s*[^']*''([^;]+)", Pattern.CASE_INSENSITIVE);

	private static final Pattern CONTENT_DISPOSITION_FILENAME_PATTERN =
			Pattern.compile("filename\\s*=\\s*\"?([^\";]+)\"?", Pattern.CASE_INSENSITIVE);

	/**
	 * True if the response signals an actual file download (as opposed to e.g. a JSON/HTML response
	 * that just happens to have a {@link HttpRequest#getDownloadTarget()} configured "just in case"),
	 * i.e. a "Content-Disposition: attachment[; ...]" response header is present. A missing header or
	 * an explicit "inline" disposition (meant to be shown in the browser/client, not saved) is not
	 * treated as a download.
	 */
	private static boolean isFileDownloadResponse(final Map<String, String> headers) {
		final String contentDisposition = headers == null ? null : headers.get("Content-Disposition");
		return contentDisposition != null && contentDisposition.trim().toLowerCase(Locale.ROOT).startsWith("attachment");
	}

	/**
	 * Resolves the actual download target file for a {@link HttpRequest#getDownloadTarget()}: an
	 * existing directory is combined with a filename derived from the response (see
	 * {@link #resolveDownloadFileName}), any other (i.e. non-directory) target is used as the file
	 * itself. Either way, an already existing target file is never overwritten (see
	 * {@link #resolveNonCollidingFile}).
	 */
	private static File resolveDownloadTargetFile(final File downloadTarget, final Map<String, String> headers, final String requestedUrl) {
		final File candidateFile = downloadTarget.isDirectory()
				? new File(downloadTarget, resolveDownloadFileName(headers, requestedUrl))
				: downloadTarget;
		return resolveNonCollidingFile(candidateFile);
	}

	/**
	 * Derives a download filename from the response, preferring the "Content-Disposition" header's
	 * filename (RFC 6266, both the plain "filename=" parameter and the RFC 5987 encoded "filename*="
	 * parameter, the latter taking precedence as it is meant for non-ASCII names), falling back to the
	 * last path segment of the requested URL, and finally to a generic name if neither yields anything
	 * usable.
	 */
	private static String resolveDownloadFileName(final Map<String, String> headers, final String requestedUrl) {
		final String contentDisposition = headers == null ? null : headers.get("Content-Disposition");
		if (contentDisposition != null) {
			final Matcher extendedMatcher = CONTENT_DISPOSITION_FILENAME_EXTENDED_PATTERN.matcher(contentDisposition);
			if (extendedMatcher.find()) {
				try {
					// RFC 5987 percent encoding has no '+' for blanks, so a literal '+' must be kept
					final String decoded = URLDecoder.decode(extendedMatcher.group(1).trim().replace("+", "%2B"), StandardCharsets.UTF_8);
					if (NetworkUtilities.isNotBlank(decoded)) {
						return sanitizeDownloadFileName(decoded);
					}
				} catch (@SuppressWarnings("unused") final IllegalArgumentException e) {
					// Malformed percent encoding: fall back to the plain filename parameter
				}
			}

			final Matcher simpleMatcher = CONTENT_DISPOSITION_FILENAME_PATTERN.matcher(contentDisposition);
			if (simpleMatcher.find()) {
				final String value = simpleMatcher.group(1).trim();
				if (NetworkUtilities.isNotBlank(value)) {
					return sanitizeDownloadFileName(value);
				}
			}
		}

		if (requestedUrl != null) {
			String path = requestedUrl;
			final int queryIndex = path.indexOf('?');
			if (queryIndex >= 0) {
				path = path.substring(0, queryIndex);
			}
			final String lastSegment = path.substring(path.lastIndexOf('/') + 1);
			if (NetworkUtilities.isNotBlank(lastSegment)) {
				try {
					// A '+' in an URL path is a literal '+', not a blank
					return sanitizeDownloadFileName(URLDecoder.decode(lastSegment.replace("+", "%2B"), StandardCharsets.UTF_8));
				} catch (@SuppressWarnings("unused") final Exception e) {
					return sanitizeDownloadFileName(lastSegment);
				}
			}
		}

		return "download";
	}

	/**
	 * Strips path separators and other characters that must not end up in a plain file name (e.g. a
	 * maliciously crafted Content-Disposition header trying to escape the target directory via "../"
	 * or an absolute path).
	 */
	private static String sanitizeDownloadFileName(final String rawFileName) {
		String fileName = rawFileName.replace('\\', '/');
		final int lastSlash = fileName.lastIndexOf('/');
		if (lastSlash >= 0) {
			fileName = fileName.substring(lastSlash + 1);
		}
		// Characters not allowed in Windows file names, e.g. ':' would create an NTFS alternate data stream
		final StringBuilder sanitizedFileName = new StringBuilder();
		for (final char c : fileName.toCharArray()) {
			sanitizedFileName.append(c < ' ' || "<>:\"|?*".indexOf(c) >= 0 ? '_' : c);
		}
		// Windows ignores trailing dots and blanks
		fileName = sanitizedFileName.toString().trim().replaceAll("[. ]+$", "");
		if (fileName.isEmpty()) {
			return "download";
		}
		return fileName;
	}

	/**
	 * If "candidateFile" already exists, appends an ascending " (n)" suffix before the file extension
	 * until a non-existing path is found - the same collision handling a browser applies to downloads
	 * (e.g. "report.pdf", "report (1).pdf", "report (2).pdf", ...).
	 */
	private static File resolveNonCollidingFile(final File candidateFile) {
		if (!candidateFile.exists()) {
			return candidateFile;
		}

		final File parentDir = candidateFile.getParentFile();
		final String name = candidateFile.getName();
		final int dotIndex = name.lastIndexOf('.');
		final String baseName = dotIndex > 0 ? name.substring(0, dotIndex) : name;
		final String extension = dotIndex > 0 ? name.substring(dotIndex) : "";

		int suffix = 1;
		File candidate;
		do {
			candidate = new File(parentDir, baseName + " (" + suffix + ")" + extension);
			suffix++;
		} while (candidate.exists());

		return candidate;
	}

	/**
	 * Compares two URIs for "same origin" (scheme + host + effective port), the way a browser would
	 * decide whether credentials (Authorization header, Cookies) may be forwarded to a redirect target.
	 * A missing port is resolved to the scheme's default port (443 for https, 80 otherwise) so that
	 * e.g. "https://example.com" and "https://example.com:443" are correctly treated as the same origin.
	 */
	private static boolean isSameOrigin(final URI uriA, final URI uriB) {
		if (uriA.getHost() == null || uriB.getHost() == null) {
			return false;
		}
		if (!uriA.getHost().equalsIgnoreCase(uriB.getHost())) {
			return false;
		}
		final String schemeA = uriA.getScheme() == null ? "" : uriA.getScheme().toLowerCase(Locale.ROOT);
		final String schemeB = uriB.getScheme() == null ? "" : uriB.getScheme().toLowerCase(Locale.ROOT);
		if (!schemeA.equals(schemeB)) {
			return false;
		}
		return getEffectivePort(uriA, schemeA) == getEffectivePort(uriB, schemeB);
	}

	private static int getEffectivePort(final URI uri, final String scheme) {
		if (uri.getPort() != -1) {
			return uri.getPort();
		} else if ("https".equals(scheme)) {
			return 443;
		} else {
			return 80;
		}
	}

	private static String encodeForCookie(final String value) {
		if (value == null) {
			return value;
		} else {
			return value.replace(";", "%3B").replace("=", "%3D");
		}
	}

	/**
	 * Generates a random boundary for multipart data.
	 *
	 * @return a boundary of 32 letters and digits
	 * @throws Exception
	 *             if no secure random generator is available
	 */
	public static String generateBoundary() throws Exception {
		final char[] availableChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".toCharArray();
		final Random random = new SecureRandom();
		final char[] boundary = new char[32];
		for (int i = 0; i < 32; i++) {
			boundary[i] = availableChars[random.nextInt(availableChars.length)];
		}
		return new String(boundary);
	}

	/**
	 * Returns the TLS certificate of a server without checking it, preferring a certificate with
	 * subject alternative names (usually the server's own certificate).
	 *
	 * @param hostnameOrIp
	 *            the host
	 * @param port
	 *            the port
	 * @param proxy
	 *            the proxy, null for a direct connection
	 * @return the certificate, or null if the server sent none
	 * @throws Exception
	 *             if the connection fails
	 */
	public static X509Certificate getServerTlsCertificate(final String hostnameOrIp, final int port, final Proxy proxy)
			throws Exception {
		final HttpsURLConnection urlConnection = (HttpsURLConnection) URI.create("https://" + hostnameOrIp + ":" + port)
				.toURL().openConnection(proxy == null ? Proxy.NO_PROXY : proxy);
		final SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
		sslContext.init(null, new TrustManager[] { TrustManagerUtilities.createTrustAllTrustManager() },
				new java.security.SecureRandom());
		final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
		urlConnection.setSSLSocketFactory(sslSocketFactory);
		urlConnection.setHostnameVerifier(TRUSTALLHOSTNAMES_HOSTNAMEVERIFIER);
		urlConnection.connect();
		Certificate[] certificates;
		try {
			certificates = urlConnection.getServerCertificates();
		} finally {
			urlConnection.disconnect();
		}
		for (final Certificate certificate : certificates) {
			if (certificate instanceof X509Certificate) {
				// Take the first certificate with alternative names
				if (((X509Certificate) certificate).getSubjectAlternativeNames() != null) {
					return (X509Certificate) certificate;
				}
			}
		}
		for (final Certificate certificate : certificates) {
			if (certificate instanceof X509Certificate) {
				// Take the first X509Certificate available, even without alternative names
				return (X509Certificate) certificate;
			}
		}
		return null;
	}

	/**
	 * Creates an HTTP proxy from a text like "proxy.example.com:3128", "http://[::1]:3128/" or
	 * "DIRECT". The port defaults to 8080.
	 *
	 * @param proxyString
	 *            the proxy text, null, empty or "DIRECT" for no proxy
	 * @return the proxy, {@link Proxy#NO_PROXY} for no proxy
	 * @throws NumberFormatException
	 *             if the port is no number
	 * @throws IllegalArgumentException
	 *             if a bracketed IPv6 address is not closed
	 */
	public static Proxy getProxyFromString(String proxyString) {
		if (proxyString == null || proxyString.trim().length() == 0 || "DIRECT".equalsIgnoreCase(proxyString.trim())) {
			return Proxy.NO_PROXY;
		} else {
			proxyString = proxyString.trim();
			if (proxyString.toLowerCase(Locale.ROOT).startsWith("http://")) {
				proxyString = proxyString.substring(7);
			} else if (proxyString.toLowerCase(Locale.ROOT).startsWith("https://")) {
				proxyString = proxyString.substring(8);
			}

			// A trailing path like in "http://proxy:3128/" is no part of the address
			if (proxyString.indexOf('/') >= 0) {
				proxyString = proxyString.substring(0, proxyString.indexOf('/'));
			}

			String proxyHost = proxyString;
			String proxyPort = "8080";
			if (proxyHost.startsWith("[")) {
				// Bracketed IPv6 address like "[::1]:3128"
				final int closingBracketIndex = proxyHost.indexOf(']');
				if (closingBracketIndex < 0) {
					throw new IllegalArgumentException("Invalid proxy: missing closing ']' for IPv6 address: " + proxyString);
				}
				if (proxyHost.length() > closingBracketIndex + 1 && proxyHost.charAt(closingBracketIndex + 1) == ':') {
					proxyPort = proxyHost.substring(closingBracketIndex + 2);
				}
				proxyHost = proxyHost.substring(1, closingBracketIndex);
			} else if (proxyHost.contains(":")) {
				proxyPort = proxyHost.substring(proxyHost.indexOf(":") + 1);
				proxyHost = proxyHost.substring(0, proxyHost.indexOf(":"));
			}
			return new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHost, Integer.parseInt(proxyPort)));
		}
	}

	/**
	 * Returns the IP address of the server of a connection: the "X-Real-IP" or first
	 * "X-Forwarded-For" response header, if present, else the resolved host of the URL.
	 *
	 * @param connection
	 *            the connection
	 * @return the IP address, or null if it cannot be determined
	 */
	public static String getIpAddress(final HttpURLConnection connection) {
		try {
			return getIpAddress(connection.getHeaderField("X-Real-IP"), connection.getHeaderField("X-Forwarded-For"),
					connection.getURL().getHost());
		} catch (@SuppressWarnings("unused") final Exception e) {
			return null;
		}
	}

	private static String getIpAddress(final String realIpHeaderValue, final String forwardedForHeaderValue, final String host) {
		try {
			String ip = realIpHeaderValue;

			if (ip == null) {
				ip = forwardedForHeaderValue;
				if (ip != null) {
					ip = ip.split(",")[0].trim();
				}
			}

			if (ip == null) {
				final InetAddress address = InetAddress.getByName(host);
				ip = address.getHostAddress();
			}
			return ip;
		} catch (@SuppressWarnings("unused") final Exception e) {
			return null;
		}
	}
}
