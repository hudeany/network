package de.soderer.network;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import de.soderer.network.HttpRequest.UploadFileAttachment;
import de.soderer.network.utilities.CaseInsensitiveLinkedMap;

public class HttpUtilities {
	private static boolean debugLog = false;
	private static String TLS_VERSION = "TLS"; // Also possible definitions "TLSv1.2", "TLSv1.3"

	private static HostnameVerifier TRUSTALLHOSTNAMES_HOSTNAMEVERIFIER = (hostname, session) -> true;

	/**
	 * Use systems default proxy, if set on JVM start.
	 * Use systems default KeyStore to check TLS server certificates.
	 *
	 * @param httpRequest
	 * @return
	 * @throws Exception
	 */
	public static HttpResponse executeHttpRequest(final HttpRequest httpRequest) throws Exception {
		return executeHttpRequest(httpRequest, null, (TrustManager) null);
	}

	/**
	 * Use systems default proxy, if set on JVM start.
	 * To override default proxy usage use "executeHttpRequest(httpRequest, Proxy.NO_PROXY)"
	 *
	 * Use systems default KeyStore to check TLS server certificates.
	 *
	 * @param httpRequest
	 * @return
	 * @throws Exception
	 */
	public static HttpResponse executeHttpRequest(final HttpRequest httpRequest, final Proxy proxy) throws Exception {
		return executeHttpRequest(httpRequest, proxy, (TrustManager) null);
	}

	public static HttpResponse executeHttpRequest(final HttpRequest httpRequest, final Proxy proxy, final KeyStore trustedKeyStore) throws Exception {
		if (trustedKeyStore.size() <= 0) {
			throw new Exception("No trusted certificate aliases found in defined trusted keystore");
		} else {
			return executeHttpRequest(httpRequest, proxy, TrustManagerUtilities.createTrustManagerForKeyStore(trustedKeyStore));
		}
	}

	public static HttpResponse executeHttpRequest(final HttpRequest httpRequest, final Proxy proxy, final TrustManager trustManager) throws Exception {
		return executeHttpRequest(httpRequest, proxy, null, null, trustManager);
	}

	public static HttpResponse executeHttpRequest(final HttpRequest httpRequest, final Proxy proxy, final String proxyUsername, final String proxyPassword, final TrustManager trustManager) throws Exception {
		try {
			String requestedUrl = httpRequest.getUrlWithProtocol();

			// Check for already in URL included GET parameters
			String parametersFromUrl;
			if (requestedUrl.contains("?")) {
				if (requestedUrl.contains("#")) {
					parametersFromUrl = requestedUrl.substring(requestedUrl.indexOf("?") + 1, requestedUrl.indexOf("#"));
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
				final String getParameterString = convertToParameterString(httpRequest.getUrlParameters(), httpRequest.getEncoding());
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

			final HttpURLConnection urlConnection = (HttpURLConnection) URI.create(requestedUrl).toURL().openConnection(proxy == null ? Proxy.NO_PROXY : proxy);
			if (httpRequest.getRequestMethod() != null) {
				urlConnection.setRequestMethod(httpRequest.getRequestMethod().name());
			}
			if (proxy != null && !proxy.equals(Proxy.NO_PROXY) && proxyUsername != null && proxyPassword != null) {
				final String proxyCredentials = proxyUsername + ":" + proxyPassword;
				urlConnection.setRequestProperty("Proxy-Authorization", "Basic " + Base64.getEncoder().encodeToString(proxyCredentials.getBytes(StandardCharsets.UTF_8)));
			}

			if (requestedUrl.toLowerCase().startsWith(HttpRequest.SECURE_HTTP_PROTOCOL_SIGN) && trustManager != null) {
				// Use special trustmanager
				final SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
				sslContext.init(null, new TrustManager[] { trustManager }, new SecureRandom());
				final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
				((HttpsURLConnection) urlConnection).setSSLSocketFactory(sslSocketFactory);
				((HttpsURLConnection) urlConnection).setHostnameVerifier(TRUSTALLHOSTNAMES_HOSTNAMEVERIFIER);
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

			if (httpRequest.getCookieData() != null && httpRequest.getCookieData().size() > 0) {
				final StringBuilder cookieValue = new StringBuilder();
				for (final Entry<String, String> cookieEntry : httpRequest.getCookieData().entrySet()) {
					if (cookieValue.length() > 0) {
						cookieValue.append("; ");
					}
					cookieValue.append(encodeForCookie(cookieEntry.getKey()) + "=" + encodeForCookie(cookieEntry.getValue()));
				}

				urlConnection.setRequestProperty(HttpRequest.HEADER_NAME_UPLOAD_COOKIE, cookieValue.toString());
			}

			final String boundary = HttpUtilities.generateBoundary();

			if (httpRequest.getRequestBodyContentStream() != null) {
				urlConnection.setDoOutput(true);
				try (OutputStream outputStream = urlConnection.getOutputStream()) {
					NetworkUtilities.copy(httpRequest.getRequestBodyContentStream(), outputStream);
					outputStream.flush();
				}
			} else if (httpRequest.getRequestBody() != null) {
				urlConnection.setDoOutput(true);

				final String httpRequestBody = httpRequest.getRequestBody();
				final Charset encoding = httpRequest.getEncoding() == null ? StandardCharsets.UTF_8 : httpRequest.getEncoding();
				final byte[] httpRequestBodyData = httpRequestBody.getBytes(encoding);

				urlConnection.setRequestProperty(HttpConstants.HTTPHEADERNAME_CONTENTLENGTH, Integer.toString(httpRequestBodyData.length));
				try (OutputStream outputStream = urlConnection.getOutputStream()) {
					outputStream.write(httpRequestBodyData);
					outputStream.flush();
				}
			} else if (httpRequest.getUploadFileAttachments() != null && httpRequest.getUploadFileAttachments().size() > 0) {
				urlConnection.setDoOutput(true);
				urlConnection.setRequestProperty(HttpConstants.HTTPHEADERNAME_CONTENTTYPE, HttpContentType.MultipartForm.getStringRepresentation() + "; boundary=" + boundary);

				try (OutputStream outputStream = urlConnection.getOutputStream()) {
					if (httpRequest.getPostParameters() != null && httpRequest.getPostParameters().size() > 0) {
						for (final Entry<String, List<Object>> entry : httpRequest.getPostParameters().entrySet()) {
							for (final Object value : entry.getValue()) {
								outputStream.write(("--" + boundary + "\r\n").getBytes(StandardCharsets.UTF_8));
								outputStream.write(("Content-Disposition: form-data; name=\"" + urlEncode(entry.getKey(), StandardCharsets.UTF_8) + "\"\r\n").getBytes(StandardCharsets.UTF_8));
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
						outputStream.write(("Content-Disposition: form-data; name=\"" + uploadFileAttachment.getHtmlInputName() + "\"; filename=\"" + uploadFileAttachment.getFileName() + "\"\r\n").getBytes(StandardCharsets.UTF_8));
						outputStream.write("\r\n".getBytes(StandardCharsets.UTF_8));

						outputStream.write(uploadFileAttachment.getData());

						outputStream.write("\r\n".getBytes(StandardCharsets.UTF_8));
					}

					outputStream.write(("--" + boundary + "--" + "\r\n").getBytes(StandardCharsets.UTF_8));
					outputStream.flush();
				}
			} else if (httpRequest.getPostParameters() != null && httpRequest.getPostParameters().size() > 0) {
				urlConnection.setDoOutput(true);
				urlConnection.setRequestProperty(HttpConstants.HTTPHEADERNAME_CONTENTTYPE, HttpContentType.HtmlForm.getStringRepresentation());
				final String httpRequestBody = convertToParameterString(httpRequest.getPostParameters(), null);

				if (debugLog) {
					System.out.println("Request Body: ");
					System.out.println(httpRequestBody);
				}

				final Charset encoding = httpRequest.getEncoding() == null ? StandardCharsets.UTF_8 : httpRequest.getEncoding();
				final byte[] httpRequestBodyData = httpRequestBody.getBytes(encoding);

				urlConnection.setRequestProperty(HttpConstants.HTTPHEADERNAME_CONTENTLENGTH, Integer.toString(httpRequestBodyData.length));
				try (OutputStream outputStream = urlConnection.getOutputStream()) {
					outputStream.write(httpRequestBodyData);
					outputStream.flush();
				}
			}

			urlConnection.connect();

			final Map<String, String> headers = new CaseInsensitiveLinkedMap<>();
			for (final String headerName : urlConnection.getHeaderFields().keySet()) {
				headers.put(headerName, urlConnection.getHeaderField(headerName));
			}

			Charset encoding = StandardCharsets.UTF_8;
			if (headers.containsKey(HttpConstants.HTTPHEADERNAME_CONTENTTYPE)) {
				String contentType = headers.get(HttpConstants.HTTPHEADERNAME_CONTENTTYPE);
				if (contentType != null && contentType.toLowerCase().contains("charset=")) {
					contentType = contentType.toLowerCase();
					encoding = Charset.forName(contentType.substring(contentType.indexOf("charset=") + 8).trim());
				}
			}

			Map<String, String> cookiesMap = null;
			if (headers.containsKey(HttpRequest.HEADER_NAME_DOWNLOAD_COOKIE)) {
				final String cookiesData = headers.get(HttpRequest.HEADER_NAME_DOWNLOAD_COOKIE);
				if (cookiesData != null) {
					cookiesMap = new LinkedHashMap<>();
					for (final String cookie : cookiesData.split(";")) {
						final String[] cookieParts = cookie.split("=");
						if (cookieParts.length == 2) {
							cookiesMap.put(urlDecode(cookieParts[0].trim(), StandardCharsets.UTF_8), urlDecode(cookieParts[1].trim(), StandardCharsets.UTF_8));
						}
					}
				}
			}

			final int httpResponseCode = urlConnection.getResponseCode();
			if (httpResponseCode < HttpURLConnection.HTTP_BAD_REQUEST) {
				if (httpRequest.getDownloadStream() != null && 200 <= httpResponseCode && httpResponseCode <= 299) {
					NetworkUtilities.copy(urlConnection.getInputStream(), httpRequest.getDownloadStream());
					return new HttpResponse(httpResponseCode, urlConnection.getResponseMessage(), "File downloaded", urlConnection.getContentType(), headers, cookiesMap);
				} else if (httpRequest.getDownloadFile() != null && 200 <= httpResponseCode && httpResponseCode <= 299) {
					try (FileOutputStream downloadFileOutputStream = new FileOutputStream(httpRequest.getDownloadFile())) {
						NetworkUtilities.copy(urlConnection.getInputStream(), downloadFileOutputStream);
						return new HttpResponse(httpResponseCode, urlConnection.getResponseMessage(), "File downloaded", urlConnection.getContentType(), headers, cookiesMap);
					} catch (final Exception e) {
						if (httpRequest.getDownloadFile().exists()) {
							httpRequest.getDownloadFile().delete();
						}
						throw e;
					}
				} else {
					try (BufferedReader httpResponseContentReader = new BufferedReader(new InputStreamReader(urlConnection.getInputStream(), encoding))) {
						final StringBuilder httpResponseContent = new StringBuilder();
						String httpResponseContentLine;
						while ((httpResponseContentLine = httpResponseContentReader.readLine()) != null) {
							if (httpResponseContent.length() > 0) {
								httpResponseContent.append("\n");
							}
							httpResponseContent.append(httpResponseContentLine);
						}
						return new HttpResponse(httpResponseCode, urlConnection.getResponseMessage(), httpResponseContent.toString(), urlConnection.getContentType(), headers, cookiesMap);
					} catch (@SuppressWarnings("unused") final Exception e) {
						return new HttpResponse(httpResponseCode, urlConnection.getResponseMessage(), null, null, headers, cookiesMap);
					}
				}
			} else if ((httpResponseCode == HttpURLConnection.HTTP_MOVED_TEMP || httpResponseCode == HttpURLConnection.HTTP_MOVED_PERM) && httpRequest.isFollowRedirects()) {
				// Optionally follow redirections (HttpCodes 301 and 302)
				final String redirectUrl = urlConnection.getHeaderField("Location");
				if (NetworkUtilities.isNotBlank(redirectUrl)) {
					final HttpRequest redirectedHttpRequest = new HttpRequest(httpRequest.getRequestMethod(), redirectUrl);
					return executeHttpRequest(redirectedHttpRequest, proxy, trustManager);
				} else {
					throw new Exception("Redirection url was empty");
				}
			} else {
				try (BufferedReader httpResponseContentReader = new BufferedReader(new InputStreamReader(urlConnection.getErrorStream(), encoding))) {
					final StringBuilder httpResponseContent = new StringBuilder();
					String httpResponseContentLine;
					while ((httpResponseContentLine = httpResponseContentReader.readLine()) != null) {
						if (httpResponseContent.length() > 0) {
							httpResponseContent.append("\n");
						}
						httpResponseContent.append(httpResponseContentLine);
					}
					return new HttpResponse(httpResponseCode, urlConnection.getResponseMessage(), httpResponseContent.toString(), urlConnection.getContentType(), headers, cookiesMap);
				} catch (@SuppressWarnings("unused") final Exception e) {
					return new HttpResponse(httpResponseCode, urlConnection.getResponseMessage(), null, null, headers, cookiesMap);
				}
			}
		} catch (final Exception e) {
			throw e;
		}
	}

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

	public static String urlEncode(final String data, final Charset charset) {
		try {
			return URLEncoder.encode(data, charset.name());
		} catch (final UnsupportedEncodingException e) {
			// Cannot occur, because of the usage of Charset class
			throw new RuntimeException(e);
		}
	}

	public static String urlDecode(final String data, final Charset charset) {
		try {
			return URLDecoder.decode(data, charset.name());
		} catch (final UnsupportedEncodingException e) {
			// Cannot occur, because of the usage of Charset class
			throw new RuntimeException(e);
		}
	}

	public static void pingUrlWithoutSslCheckNoWaitForAnswer(final String pingUrl, final Proxy proxy) throws IOException, NoSuchAlgorithmException, KeyManagementException {
		InputStream downloadStream = null;
		try {
			if (pingUrl.startsWith("https")) {
				// Deactivate SSL-Certificates check
				final SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
				final TrustManager[] tms = new TrustManager[] {
						new X509TrustManager() {
							@Override
							public X509Certificate[] getAcceptedIssuers() {
								return null;
							}

							@Override
							public void checkServerTrusted(final X509Certificate[] arg0, final String arg1) throws CertificateException {
								// nothing to do
							}

							@Override
							public void checkClientTrusted(final X509Certificate[] arg0, final String arg1) throws CertificateException {
								// nothing to do
							}
						}
				};
				sslContext.init(null, tms, null);
				final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
				final HttpsURLConnection urlConnection = (HttpsURLConnection) URI.create(pingUrl).toURL().openConnection(proxy == null ? Proxy.NO_PROXY : proxy);
				urlConnection.setSSLSocketFactory(sslSocketFactory);
				urlConnection.setRequestMethod("POST");
				urlConnection.setConnectTimeout(5000);
				urlConnection.setReadTimeout(100);
				urlConnection.setDoInput(true);
				urlConnection.setDoOutput(false);
				downloadStream = urlConnection.getInputStream();
			} else {
				final HttpURLConnection urlConnection = (HttpURLConnection) URI.create(pingUrl).toURL().openConnection(proxy == null ? Proxy.NO_PROXY : proxy);
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

	public static Map<String, List<String>> createHtmlFormMimetypeHeader(final Charset encoding) {
		final Map<String, List<String>> returnMap = new HashMap<>();
		final List<String> valueList = new ArrayList<>();
		if (encoding == null) {
			valueList.add(HttpContentType.HtmlForm.getStringRepresentation());
		} else {
			valueList.add(HttpContentType.HtmlForm.getStringRepresentation() + "; charset=" + encoding.name().toLowerCase());
		}
		returnMap.put(HttpConstants.HTTPHEADERNAME_CONTENTTYPE, valueList);
		return returnMap;
	}

	public static String addUrlParameter(final String url, final String parameterName, final Object parameterValue, final Charset encodingCharSet) {
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

	public static String addUrlParameter(final String url, final String escapedParameterNameAndValue) {
		final StringBuilder newUrl = new StringBuilder();
		final int insertPosition = url.indexOf('#');

		if (insertPosition < 0) {
			newUrl.append(url);
			newUrl.append(url.indexOf('?') <= -1 ? '?' : '&');
			newUrl.append(escapedParameterNameAndValue);
		} else {
			newUrl.append(url.substring(0, insertPosition));
			newUrl.append(url.indexOf('?') <= -1 ? '?' : '&');
			newUrl.append(escapedParameterNameAndValue);
			newUrl.append(url.substring(insertPosition));
		}

		return newUrl.toString();
	}

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

	public static String getPlainParameterFromHtml(final String htmlText, final String parameterName) {
		if (NetworkUtilities.isBlank(htmlText)) {
			return null;
		} else {
			final Pattern parameterPattern = Pattern.compile("\\W" + parameterName + "\\s*=(\\w*)\\W", Pattern.MULTILINE);
			final Matcher parameterMatcher = parameterPattern.matcher(htmlText);
			if (parameterMatcher.find()) {
				return parameterMatcher.group(1).trim();
			} else {
				return null;
			}
		}
	}

	public static String getQuotedParameterFromHtml(final String htmlText, final String parameterName) {
		if (NetworkUtilities.isBlank(htmlText)) {
			return null;
		} else {
			final Pattern parameterPattern = Pattern.compile("\\W" + parameterName + "\\s*=\\s\"(\\w*)\"\\W", Pattern.MULTILINE);
			final Matcher parameterMatcher = parameterPattern.matcher(htmlText);
			if (parameterMatcher.find()) {
				return parameterMatcher.group(1).trim();
			} else {
				return null;
			}
		}
	}

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
				return "Temporary Redirect";
			case HttpURLConnection.HTTP_SEE_OTHER:
				// 303
				return "See Other";
			case HttpURLConnection.HTTP_NOT_MODIFIED:
				// 304
				return "Not Modified";
			case HttpURLConnection.HTTP_USE_PROXY:
				// 305
				return "Use Proxy";
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

	public static String createBasicAuthenticationHeaderValue(final String username, final String password) {
		return "Basic " + Base64.getEncoder().encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
	}

	private static String encodeForCookie(final String value) {
		if (value == null) {
			return value;
		} else {
			return value.replace(";", "%3B").replace("=", "%3D");
		}
	}

	public static String generateBoundary() throws Exception {
		final char[] availableChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".toCharArray();
		final Random random = new SecureRandom();
		final char[] boundary = new char[32];
		for (int i = 0; i < 32; i++) {
			boundary[i] = availableChars[random.nextInt(availableChars.length)];
		}
		return new String(boundary);
	}

	public static X509Certificate getServerTlsCertificate(final String hostnameOrIp, final int port, final Proxy proxy) throws Exception {
		final HttpsURLConnection urlConnection = (HttpsURLConnection) URI.create("https://" + hostnameOrIp + ":" + port).toURL().openConnection(proxy == null ? Proxy.NO_PROXY : proxy);
		final SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
		sslContext.init(null, new TrustManager[] { TrustManagerUtilities.createTrustAllTrustManager() }, new java.security.SecureRandom());
		final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
		urlConnection.setSSLSocketFactory(sslSocketFactory);
		urlConnection.setHostnameVerifier(TRUSTALLHOSTNAMES_HOSTNAMEVERIFIER);
		urlConnection.connect();
		final Certificate[] certificates = urlConnection.getServerCertificates();
		for (final Certificate certificate : certificates) {
			if (certificate instanceof X509Certificate) {
				// Take the first certificate with alternative names
				if (((X509Certificate)certificate).getSubjectAlternativeNames() != null) {
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

	public static Proxy getProxyFromString(final String proxyString) {
		if (proxyString == null || proxyString.trim().length() == 0 || "DIRECT".equalsIgnoreCase(proxyString)) {
			return Proxy.NO_PROXY;
		} else {
			String proxyHost = proxyString;
			String proxyPort = "8080";
			if (proxyHost.contains(":")) {
				proxyPort = proxyHost.substring(proxyHost.indexOf(":") + 1);
				proxyHost = proxyHost.substring(0, proxyHost.indexOf(":"));
			}
			return new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHost, Integer.parseInt(proxyPort)));
		}
	}
}
