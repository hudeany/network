package de.soderer.network;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class HttpRequest {
	/** Default maximum size of the header block, guards against resource-exhaustion from malformed/malicious requests */
	public static final int DEFAULT_MAX_HEADER_SIZE = 64 * 1024; // 64 KB

	/** Default maximum body size (Content-Length or accumulated chunked size) */
	public static final int DEFAULT_MAX_BODY_SIZE = 10 * 1024 * 1024; // 10 MB

	private final HttpMethod requestMethod;
	private final String url;
	private Charset encoding = StandardCharsets.UTF_8;

	private int connectTimeoutMillis = -1;
	private int readTimeoutMillis = -1;

	private final Map<String, String> headers = new LinkedHashMap<>();
	private final Map<String, List<Object>> urlParameters = new HashMap<>();
	private final Map<String, List<Object>> postParameters= new HashMap<>();
	private String requestBody = null;
	private InputStream requestBodyContentStream = null;
	private final List<UploadFileAttachment> uploadFileAttachments = new ArrayList<>();
	private OutputStream downloadStream = null;
	private File downloadFile = null;
	private final Map<String, Object> pathParameterData = new LinkedHashMap<>();
	private final Map<String, String> cookieData = new LinkedHashMap<>();

	/**
	 * Controls automatic redirect following:
	 * <ul>
	 *   <li>{@code 0} (default): do not follow redirects</li>
	 *   <li>negative: follow redirects without a hop limit</li>
	 *   <li>positive: follow redirects up to this many hops, then fail</li>
	 * </ul>
	 */
	private int maxRedirects = 0;

	/** Default hop limit used by the {@link #setFollowRedirects(boolean)} convenience method */
	public static final int DEFAULT_MAX_REDIRECTS = 25;

	/**
	 * Temporary accessible url connection for interrupting the connection on long timeouts
	 */
	private volatile HttpURLConnection httpURLConnection = null;

	public class UploadFileAttachment {
		private String htmlInputName;
		private String fileName;
		private byte[] data;

		public UploadFileAttachment(final String htmlInputName, final String fileName, final byte[] data) {
			super();
			this.htmlInputName = htmlInputName;
			this.fileName = fileName;
			this.data = data;
		}

		public String getHtmlInputName() {
			return htmlInputName;
		}

		public UploadFileAttachment setHtmlInputName(final String htmlInputName) {
			this.htmlInputName = htmlInputName;
			return this;
		}

		public String getFileName() {
			return fileName;
		}

		public UploadFileAttachment setFileName(final String fileName) {
			this.fileName = fileName;
			return this;
		}

		public byte[] getData() {
			return data;
		}

		public UploadFileAttachment setData(final byte[] data) {
			this.data = data;
			return this;
		}
	}

	/**
	 * Http POST Request
	 *
	 * @param url
	 * @throws Exception
	 */
	public HttpRequest(final String url) throws Exception {
		this(HttpMethod.POST, url);
	}

	public HttpRequest(final HttpMethod requestMethod, final String url) throws Exception {
		if (NetworkUtilities.isBlank(url)) {
			throw new Exception("Invalid empty url");
		}
		this.requestMethod = requestMethod == null ? HttpMethod.GET : requestMethod;
		this.url = url;
	}

	public HttpMethod getRequestMethod() {
		return requestMethod;
	}

	public String getUrl() {
		return url;
	}

	/**
	 * Check for protocol "https://" or "http://" (fallback: "http://")
	 *
	 * @return
	 * @throws Exception
	 */
	public String getUrlWithProtocol() throws Exception {
		if (NetworkUtilities.isBlank(url)) {
			throw new Exception("Invalid empty URL for http request");
		} else if (url.toLowerCase().startsWith(HttpConstants.SECURE_HTTP_PROTOCOL_SIGN) || url.toLowerCase().startsWith(HttpConstants.HTTP_PROTOCOL_SIGN)) {
			return url;
		} else {
			return HttpConstants.SECURE_HTTP_PROTOCOL_SIGN + url;
		}
	}

	public Map<String, String> getHeaders() {
		return headers;
	}

	public HttpRequest addHeader(final String key, final String value) {
		headers.put(key, value);

		return this;
	}

	public HttpRequest addUserAgentHeader(final String userAgent) throws Exception {
		if (headers.containsKey(HttpConstants.HTTPHEADERNAME_USER_AGENT)) {
			throw new Exception("Request already contains a UserAgentHeader");
		} else {
			addHeader(HttpConstants.HTTPHEADERNAME_USER_AGENT, userAgent);

			return this;
		}
	}

	public HttpRequest addBasicAuthenticationHeader(final String username, final String password) throws Exception {
		if (headers.containsKey(HttpConstants.HTTPHEADERNAME_AUTHORIZATION)) {
			throw new Exception("Request already contains a BasicAuthenticationHeader");
		} else {
			addHeader(HttpConstants.HTTPHEADERNAME_AUTHORIZATION, HttpUtilities.createBasicAuthenticationHeaderValue(username, password));

			return this;
		}
	}

	public Map<String, List<Object>> getUrlParameters() {
		return urlParameters;
	}

	public HttpRequest addUrlParameter(final String key, final Object value) {
		if (!urlParameters.containsKey(key)) {
			urlParameters.put(key, new ArrayList<>());
		}
		urlParameters.get(key).add(value);

		return this;
	}

	public Map<String, List<Object>> getPostParameters() {
		return postParameters;
	}

	public HttpRequest addPostParameter(final String key, final Object value) throws Exception {
		if (requestBody != null) {
			throw new Exception("RequestBody is already set. Post parameters cannot be set therefore");
		} else if (requestBodyContentStream != null) {
			throw new Exception("RequestBodyContentStream is already set. Post parameters cannot be set therefore");
		} else {
			if (!postParameters.containsKey(key)) {
				postParameters.put(key, new ArrayList<>());
			}
			postParameters.get(key).add(value);

			return this;
		}
	}

	public List<UploadFileAttachment> getUploadFileAttachments() {
		return uploadFileAttachments;
	}

	public HttpRequest addUploadFileData(final String htmlInputName, final String fileName, final byte[] data) throws Exception {
		if (requestBody != null) {
			throw new Exception("RequestBody is already set. UploadFileAttachments cannot be set therefore");
		} else if (requestBodyContentStream != null) {
			throw new Exception("RequestBodyContentStream is already set. UploadFileAttachments cannot be set therefore");
		} else {
			uploadFileAttachments.add(new UploadFileAttachment(htmlInputName, fileName, data));
			return this;
		}
	}

	public OutputStream getDownloadStream() {
		return downloadStream;
	}

	public HttpRequest setDownloadStream(final OutputStream downloadStream) throws Exception {
		if (downloadFile != null) {
			throw new Exception("DownloadFile is already set. DownloadStream cannot be set therefore");
		} else {
			this.downloadStream = downloadStream;

			return this;
		}
	}

	public File getDownloadFile() {
		return downloadFile;
	}

	public HttpRequest setDownloadFile(final File downloadFile) throws Exception {
		if (downloadStream != null) {
			throw new Exception("DownloadStream is already set. DownloadFile cannot be set therefore");
		} else {
			this.downloadFile = downloadFile;

			return this;
		}
	}

	public Map<String, Object> getPathParameterData() {
		return pathParameterData;
	}

	public HttpRequest addPathParameter(final String key, final Object value) {
		pathParameterData.put(key, value);

		return this;
	}

	public Map<String, String> getCookieData() {
		return cookieData;
	}

	public HttpRequest addCookieData(final String name, final String value) {
		cookieData.put(name, value);

		return this;
	}

	public Charset getEncoding() {
		return encoding;
	}

	public HttpRequest setEncoding(final Charset encoding) {
		this.encoding = encoding;

		return this;
	}

	/**
	 * Timeout for build up the connection to the server
	 */
	public HttpRequest setConnectionTimeoutMillis(final int connectTimeoutMillis) {
		this.connectTimeoutMillis = connectTimeoutMillis;

		return this;
	}

	public int getConnectTimeoutMillis() {
		return connectTimeoutMillis;
	}

	/**
	 * Timeout for wait for the servers response after sending the request
	 */
	public HttpRequest setReadTimeoutMillis(final int readTimeoutMillis) {
		this.readTimeoutMillis = readTimeoutMillis;

		return this;
	}

	public int getReadTimeoutMillis() {
		return readTimeoutMillis;
	}

	public String getRequestBody() {
		return requestBody;
	}

	public InputStream getRequestBodyContentStream() {
		return requestBodyContentStream;
	}

	public HttpRequest setRequestBody(final String requestBody) throws Exception {
		if (postParameters.size() > 0) {
			throw new Exception("Post parameters are already set. RequestBody cannot be set therefore");
		} else if (uploadFileAttachments.size() > 0) {
			throw new Exception("UploadFileAttachments are already set. RequestBody cannot be set therefore");
		} else if (requestBodyContentStream != null) {
			throw new Exception("RequestBodyContentStream is already set. RequestBody cannot be set therefore");
		} else {
			this.requestBody = requestBody;

			return this;
		}
	}

	public HttpRequest setRequestBodyContentStream(final InputStream requestBodyContentStream) throws Exception {
		if (postParameters.size() > 0) {
			throw new Exception("Post parameters are already set. RequestBody cannot be set therefore");
		} else if (uploadFileAttachments.size() > 0) {
			throw new Exception("UploadFileAttachments are already set. RequestBody cannot be set therefore");
		} else if (requestBody != null) {
			throw new Exception("RequestBody is already set. RequestBodyContentStream cannot be set therefore");
		} else {
			this.requestBodyContentStream = requestBodyContentStream;

			return this;
		}
	}

	public int getMaxRedirects() {
		return maxRedirects;
	}

	/**
	 * @param maxRedirects 0 = do not follow redirects, negative = follow redirects without a hop limit,
	 *                      positive = maximum number of redirect hops to follow before failing
	 */
	public HttpRequest setMaxRedirects(final int maxRedirects) {
		this.maxRedirects = maxRedirects;

		return this;
	}

	/** Convenience for existing callers: true means "follow up to {@link #DEFAULT_MAX_REDIRECTS} hops", false means "do not follow". Use {@link #setMaxRedirects(int)} for finer control (e.g. unlimited or a custom hop limit) */
	public boolean isFollowRedirects() {
		return maxRedirects != 0;
	}

	/** Convenience for existing callers: true means "follow up to {@link #DEFAULT_MAX_REDIRECTS} hops", false means "do not follow". Use {@link #setMaxRedirects(int)} for finer control (e.g. unlimited or a custom hop limit) */
	public HttpRequest setFollowRedirects(final boolean followRedirects) {
		maxRedirects = followRedirects ? DEFAULT_MAX_REDIRECTS : 0;

		return this;
	}

	public HttpURLConnection getHttpURLConnection() {
		return httpURLConnection;
	}

	protected void setHttpURLConnection(final HttpURLConnection httpURLConnection) {
		this.httpURLConnection = httpURLConnection;
	}

	@Override
	public String toString() {
		return requestMethod.name() + " " + url;
	}

	public void cancel() {
		if (httpURLConnection != null) {
			try {
				httpURLConnection.disconnect();
			} catch (@SuppressWarnings("unused") final Exception e) {
				// do nothing
			}
		}
	}

	/**
	 * Parses raw server-side HTTP/1.x request data (request line, headers, body) directly
	 * from a socket's InputStream and returns a populated HttpRequest instance.
	 *
	 * <p>Reads only raw bytes (never wraps the stream in a Reader), so no bytes are lost
	 * between reading the header block and reading a subsequent Content-Length or chunked
	 * body from the same underlying stream.</p>
	 *
	 * <p>{@code timeoutMillis} bounds the total time spent waiting for data across all reads
	 * performed by this method. For a real per-read timeout (so a single blocking read cannot
	 * hang forever on a stalled connection), the caller should additionally set
	 * {@code socket.setSoTimeout(timeoutMillis)} on the underlying socket before calling this
	 * method; a resulting SocketTimeoutException is simply propagated as an IOException.</p>
	 *
	 * <p>Populates: requestMethod, url (the request-target exactly as sent, including any
	 * query string), urlParameters (parsed from the query string), headers (duplicate header
	 * names are combined with ", " per RFC 7230 3.2.2), cookieData (parsed from the "Cookie"
	 * header), and the body depending on Content-Type:</p>
	 * <ul>
	 *   <li>"application/x-www-form-urlencoded" -&gt; postParameters</li>
	 *   <li>"multipart/form-data" -&gt; postParameters (fields without filename) and
	 *       uploadFileAttachments (parts with filename)</li>
	 *   <li>anything else -&gt; requestBody, decoded using the Content-Type charset if present,
	 *       otherwise this request's current {@link #getEncoding()}</li>
	 * </ul>
	 * <p>pathParameterData is left empty since it depends on a route template unknown to this
	 * parser; populate it afterwards via {@link #addPathParameter(String, Object)} once routing
	 * has matched the request.</p>
	 */
	public static HttpRequest parseHttpRequestData(final InputStream inputStream, final int timeoutMillis) throws IOException {
		return parseHttpRequestData(inputStream, timeoutMillis, DEFAULT_MAX_HEADER_SIZE, DEFAULT_MAX_BODY_SIZE);
	}

	public static HttpRequest parseHttpRequestData(final InputStream inputStream, final int timeoutMillis, final int maxHeaderSize, final int maxBodySize) throws IOException {
		if (inputStream == null) {
			throw new IllegalArgumentException("inputStream must not be null");
		}
		if (timeoutMillis <= 0) {
			throw new IllegalArgumentException("timeoutMillis must be > 0");
		}

		final long deadline = System.currentTimeMillis() + timeoutMillis;

		final byte[] headerBytes = readHeaderBlock(inputStream, deadline, maxHeaderSize);
		final String headerBlock = new String(headerBytes, StandardCharsets.ISO_8859_1);
		final String[] lines = headerBlock.split("\r\n");
		if (lines.length == 0 || lines[0].isBlank()) {
			throw new IOException("Empty or invalid HTTP request");
		}

		// Request line, e.g. "GET /abc?b=10&c=11 HTTP/1.1"
		final String requestLine = lines[0];
		final String[] requestLineParts = requestLine.split(" ", 3);
		if (requestLineParts.length != 3) {
			throw new IOException("Invalid HTTP request line: '" + requestLine + "'");
		}

		final HttpMethod method;
		try {
			method = HttpMethod.valueOf(requestLineParts[0].toUpperCase());
		} catch (@SuppressWarnings("unused") final IllegalArgumentException e) {
			throw new IOException("Unsupported HTTP method: '" + requestLineParts[0] + "'");
		}

		final String rawRequestTarget = requestLineParts[1];

		final HttpRequest request;
		try {
			request = new HttpRequest(method, rawRequestTarget);
		} catch (final Exception e) {
			throw new IOException("Could not create HttpRequest: " + e.getMessage(), e);
		}

		final int queryIndex = rawRequestTarget.indexOf('?');
		if (queryIndex >= 0) {
			final String queryString = rawRequestTarget.substring(queryIndex + 1);
			for (final Map.Entry<String, List<Object>> entry : parseUrlEncodedParameters(queryString).entrySet()) {
				for (final Object value : entry.getValue()) {
					request.addUrlParameter(entry.getKey(), value);
				}
			}
		}

		// Header lines
		for (int i = 1; i < lines.length; i++) {
			final String line = lines[i];
			if (line.isBlank()) {
				continue;
			}
			final int colonIndex = line.indexOf(':');
			if (colonIndex <= 0) {
				throw new IOException("Invalid header line: '" + line + "'");
			}
			final String headerName = line.substring(0, colonIndex).trim();
			final String headerValue = line.substring(colonIndex + 1).trim();
			final String existingValue = request.getHeaders().get(headerName);
			request.addHeader(headerName, existingValue == null ? headerValue : existingValue + ", " + headerValue);
		}

		// Cookies, e.g. "Cookie: sessionId=abc123; theme=dark"
		final String cookieHeader = request.getHeaders().get("Cookie");
		if (cookieHeader != null) {
			for (final String cookiePair : cookieHeader.split(";")) {
				final String trimmedPair = cookiePair.trim();
				if (trimmedPair.isEmpty()) {
					continue;
				}
				final int equalsIndex = trimmedPair.indexOf('=');
				if (equalsIndex > 0) {
					request.addCookieData(trimmedPair.substring(0, equalsIndex).trim(), trimmedPair.substring(equalsIndex + 1).trim());
				}
			}
		}

		// Body
		final String contentTypeHeader = request.getHeaders().get("Content-Type");

		final byte[] body;
		final String transferEncoding = request.getHeaders().get("Transfer-Encoding");
		if (transferEncoding != null && transferEncoding.toLowerCase().contains("chunked")) {
			body = readChunkedBody(inputStream, deadline, maxBodySize);
		} else {
			final String contentLengthValue = request.getHeaders().get("Content-Length");
			if (contentLengthValue != null) {
				final int contentLength;
				try {
					contentLength = Integer.parseInt(contentLengthValue.trim());
				} catch (@SuppressWarnings("unused") final NumberFormatException e) {
					throw new IOException("Invalid Content-Length header: '" + contentLengthValue + "'");
				}
				if (contentLength < 0) {
					throw new IOException("Negative Content-Length: " + contentLength);
				}
				if (contentLength > maxBodySize) {
					throw new IOException("Content-Length " + contentLength + " exceeds maximum allowed body size of " + maxBodySize + " bytes");
				}
				body = readExactBytes(inputStream, contentLength, deadline);
			} else {
				body = new byte[0];
			}
		}

		try {
			if (body.length > 0) {
				if (contentTypeHeader != null && contentTypeHeader.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
					final Charset bodyCharset = determineCharset(contentTypeHeader, request.getEncoding());
					final String bodyString = new String(body, bodyCharset);
					for (final Map.Entry<String, List<Object>> entry : parseUrlEncodedParameters(bodyString).entrySet()) {
						for (final Object value : entry.getValue()) {
							request.addPostParameter(entry.getKey(), value);
						}
					}
				} else if (contentTypeHeader != null && contentTypeHeader.toLowerCase().startsWith("multipart/form-data")) {
					final String boundary = extractMultipartBoundary(contentTypeHeader);
					if (boundary == null) {
						throw new IOException("Missing boundary in multipart Content-Type header: '" + contentTypeHeader + "'");
					}
					parseMultipartBody(request, body, boundary);
				} else {
					final Charset bodyCharset = determineCharset(contentTypeHeader, request.getEncoding());
					request.setRequestBody(new String(body, bodyCharset));
				}
			}
		} catch (final IOException e) {
			throw e;
		} catch (final Exception e) {
			throw new IOException("Could not apply parsed HTTP body to HttpRequest: " + e.getMessage(), e);
		}

		return request;
	}

	/**
	 * Reads raw bytes up to and including the blank line ("\r\n\r\n") that terminates the HTTP
	 * header block, and returns the header block bytes without the terminating blank line (but
	 * with the trailing "\r\n" of the last header line kept, so splitting on "\r\n" yields clean
	 * header lines).
	 */
	private static byte[] readHeaderBlock(final InputStream inputStream, final long deadline, final int maxHeaderSize) throws IOException {
		final ByteArrayOutputStream buffer = new ByteArrayOutputStream(4096);
		final int[] last4 = { -1, -1, -1, -1 };

		while (true) {
			checkDeadline(deadline);
			final int nextByte = inputStream.read();
			if (nextByte == -1) {
				throw new IOException("Unexpected end of stream while reading HTTP headers");
			}
			buffer.write(nextByte);
			if (buffer.size() > maxHeaderSize) {
				throw new IOException("HTTP header block exceeds maximum allowed size of " + maxHeaderSize + " bytes");
			}

			last4[0] = last4[1];
			last4[1] = last4[2];
			last4[2] = last4[3];
			last4[3] = nextByte;

			if (last4[0] == '\r' && last4[1] == '\n' && last4[2] == '\r' && last4[3] == '\n') {
				break;
			}
		}

		final byte[] result = buffer.toByteArray();
		return Arrays.copyOf(result, result.length - 2);
	}

	private static byte[] readExactBytes(final InputStream inputStream, final int length, final long deadline) throws IOException {
		final byte[] data = new byte[length];
		int totalRead = 0;
		while (totalRead < length) {
			checkDeadline(deadline);
			final int readCount = inputStream.read(data, totalRead, length - totalRead);
			if (readCount == -1) {
				throw new IOException("Unexpected end of stream while reading HTTP body, expected " + length + " bytes but got " + totalRead);
			}
			totalRead += readCount;
		}
		return data;
	}

	private static byte[] readChunkedBody(final InputStream inputStream, final long deadline, final int maxBodySize) throws IOException {
		final ByteArrayOutputStream result = new ByteArrayOutputStream();
		while (true) {
			checkDeadline(deadline);
			final String chunkSizeLine = readLine(inputStream, deadline);
			final String chunkSizeHex = chunkSizeLine.split(";", 2)[0].trim(); // ignore chunk extensions
			final int chunkSize;
			try {
				chunkSize = Integer.parseInt(chunkSizeHex, 16);
			} catch (@SuppressWarnings("unused") final NumberFormatException e) {
				throw new IOException("Invalid chunk size line: '" + chunkSizeLine + "'");
			}
			if (chunkSize < 0) {
				throw new IOException("Negative chunk size: " + chunkSize);
			}
			if (chunkSize == 0) {
				// consume optional trailing headers up to the final blank line
				@SuppressWarnings("unused")
				String trailerLine;
				while (!(trailerLine = readLine(inputStream, deadline)).isEmpty()) {
					// trailer headers are intentionally ignored
				}
				break;
			}
			if (result.size() + chunkSize > maxBodySize) {
				throw new IOException("Chunked body exceeds maximum allowed size of " + maxBodySize + " bytes");
			}
			final byte[] chunkData = readExactBytes(inputStream, chunkSize, deadline);
			result.write(chunkData);

			final int cr = inputStream.read();
			final int lf = inputStream.read();
			if (cr != '\r' || lf != '\n') {
				throw new IOException("Malformed chunk terminator after chunk data");
			}
		}
		return result.toByteArray();
	}

	/** Max length of a single line read via readLine() (chunk-size lines, chunk trailer headers) */
	private static final int MAX_LINE_LENGTH = 8 * 1024; // 8 KB

	private static String readLine(final InputStream inputStream, final long deadline) throws IOException {
		final ByteArrayOutputStream lineBuffer = new ByteArrayOutputStream();
		int previous = -1;
		while (true) {
			checkDeadline(deadline);
			final int current = inputStream.read();
			if (current == -1) {
				throw new IOException("Unexpected end of stream while reading line");
			}
			if (previous == '\r' && current == '\n') {
				final byte[] lineBytes = lineBuffer.toByteArray();
				return new String(lineBytes, 0, lineBytes.length - 1, StandardCharsets.ISO_8859_1);
			}
			// Without this bound, a peer that never sends a CRLF could grow this buffer without limit within
			// the timeout window (the deadline only bounds time, not size), a resource-exhaustion DoS vector.
			if (lineBuffer.size() >= MAX_LINE_LENGTH) {
				throw new IOException("Line exceeds maximum allowed length of " + MAX_LINE_LENGTH + " bytes");
			}
			lineBuffer.write(current);
			previous = current;
		}
	}

	private static void checkDeadline(final long deadline) throws IOException {
		if (System.currentTimeMillis() > deadline) {
			throw new SocketTimeoutException("Timeout while reading HTTP request data");
		}
	}

	private static Map<String, List<Object>> parseUrlEncodedParameters(final String data) {
		final Map<String, List<Object>> parameters = new LinkedHashMap<>();
		if (data == null || data.isEmpty()) {
			return parameters;
		}
		for (final String pair : data.split("&")) {
			if (pair.isEmpty()) {
				continue;
			}
			final int equalsIndex = pair.indexOf('=');
			final String key;
			final String value;
			if (equalsIndex >= 0) {
				key = urlDecode(pair.substring(0, equalsIndex));
				value = urlDecode(pair.substring(equalsIndex + 1));
			} else {
				key = urlDecode(pair);
				value = "";
			}
			parameters.computeIfAbsent(key, unusedKey -> new ArrayList<>()).add(value);
		}
		return parameters;
	}

	private static String urlDecode(final String value) {
		return URLDecoder.decode(value, StandardCharsets.UTF_8);
	}

	/** Determines the charset from a Content-Type header's "charset=" parameter, or returns the fallback */
	private static Charset determineCharset(final String contentTypeHeader, final Charset fallback) {
		if (contentTypeHeader == null) {
			return fallback;
		}
		final int charsetIndex = contentTypeHeader.toLowerCase().indexOf("charset=");
		if (charsetIndex < 0) {
			return fallback;
		}
		String charsetName = contentTypeHeader.substring(charsetIndex + "charset=".length()).trim();
		final int semicolonIndex = charsetName.indexOf(';');
		if (semicolonIndex >= 0) {
			charsetName = charsetName.substring(0, semicolonIndex).trim();
		}
		charsetName = charsetName.replace("\"", "");
		try {
			return Charset.forName(charsetName);
		} catch (@SuppressWarnings("unused") final Exception e) {
			return fallback;
		}
	}

	private static String extractMultipartBoundary(final String contentTypeHeader) {
		for (final String part : contentTypeHeader.split(";")) {
			final String trimmedPart = part.trim();
			if (trimmedPart.toLowerCase().startsWith("boundary=")) {
				return stripQuotes(trimmedPart.substring("boundary=".length()).trim());
			}
		}
		return null;
	}

	/**
	 * Splits a multipart/form-data body on the given boundary and applies each section to
	 * postParameters (form fields) or uploadFileAttachments (parts with a filename).
	 */
	private static void parseMultipartBody(final HttpRequest request, final byte[] body, final String boundary) throws Exception {
		final byte[] delimiter = ("--" + boundary).getBytes(StandardCharsets.ISO_8859_1);

		int delimiterIndex = indexOfBytes(body, delimiter, 0);
		if (delimiterIndex < 0) {
			throw new IOException("Multipart boundary not found in body");
		}

		while (true) {
			int partStart = delimiterIndex + delimiter.length;

			// closing delimiter is "--boundary--"
			if (partStart + 1 < body.length && body[partStart] == '-' && body[partStart + 1] == '-') {
				break;
			}

			// skip CRLF right after the delimiter
			if (partStart + 1 < body.length && body[partStart] == '\r' && body[partStart + 1] == '\n') {
				partStart += 2;
			}

			final int nextDelimiterIndex = indexOfBytes(body, delimiter, partStart);
			if (nextDelimiterIndex < 0) {
				throw new IOException("Unterminated multipart section in body");
			}

			// part content ends right before the trailing CRLF that precedes the next delimiter
			int partEnd = nextDelimiterIndex;
			if (partEnd >= 2 && body[partEnd - 2] == '\r' && body[partEnd - 1] == '\n') {
				partEnd -= 2;
			}

			processMultipartSection(request, body, partStart, partEnd);

			delimiterIndex = nextDelimiterIndex;
		}
	}

	private static void processMultipartSection(final HttpRequest request, final byte[] body, final int start, final int end) throws Exception {
		final byte[] headerBodySeparator = { '\r', '\n', '\r', '\n' };
		final int separatorIndex = indexOfBytes(Arrays.copyOfRange(body, start, end), headerBodySeparator, 0);
		if (separatorIndex < 0) {
			throw new IOException("Invalid multipart section: missing header/body separator");
		}

		final String sectionHeaderBlock = new String(body, start, separatorIndex, StandardCharsets.ISO_8859_1);
		final int partBodyStart = start + separatorIndex + headerBodySeparator.length;
		final byte[] partBody = Arrays.copyOfRange(body, partBodyStart, end);

		String name = null;
		String fileName = null;
		for (final String headerLine : sectionHeaderBlock.split("\r\n")) {
			final int colonIndex = headerLine.indexOf(':');
			if (colonIndex <= 0) {
				continue;
			}
			final String headerName = headerLine.substring(0, colonIndex).trim();
			final String headerValue = headerLine.substring(colonIndex + 1).trim();
			if ("Content-Disposition".equalsIgnoreCase(headerName)) {
				for (final String segment : headerValue.split(";")) {
					final String trimmedSegment = segment.trim();
					if (trimmedSegment.startsWith("name=")) {
						name = stripQuotes(trimmedSegment.substring("name=".length()));
					} else if (trimmedSegment.startsWith("filename=")) {
						fileName = stripQuotes(trimmedSegment.substring("filename=".length()));
					}
				}
			}
		}

		if (name == null) {
			throw new IOException("Multipart section without a 'name' in Content-Disposition header");
		}

		if (fileName != null) {
			request.addUploadFileData(name, fileName, partBody);
		} else {
			request.addPostParameter(name, new String(partBody, request.getEncoding()));
		}
	}

	private static String stripQuotes(final String value) {
		if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
			return value.substring(1, value.length() - 1);
		}
		return value;
	}

	private static int indexOfBytes(final byte[] data, final byte[] pattern, final int fromIndex) {
		final int maxStart = data.length - pattern.length;
		outer:
		for (int i = Math.max(fromIndex, 0); i <= maxStart; i++) {
			for (int j = 0; j < pattern.length; j++) {
				if (data[i + j] != pattern[j]) {
					continue outer;
				}
			}
			return i;
		}
		return -1;
	}
}
