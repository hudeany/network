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
import java.util.Locale;
import java.util.Map;

import de.soderer.network.utilities.CaseInsensitiveLinkedMap;

/**
 * HTTP request to be executed by {@link HttpUtilities#executeHttpRequest(HttpRequest)}, or parsed
 * from raw request data on server side by {@link #parseHttpRequestData(InputStream, int)}.
 * <p>
 * The request body is defined by exactly one of: post parameters (with optional file uploads as
 * multipart data), a request body text, or a request body stream. The response body can be
 * redirected to a stream, a file, or a download target that is only used for file downloads.
 * All setters return this request for chaining.
 * </p>
 */
public class HttpRequest {
	/** Default maximum size of the header block, guards against resource-exhaustion from malformed/malicious requests */
	public static final int DEFAULT_MAX_HEADER_SIZE = 64 * 1024; // 64 KB

	/** Default maximum body size (Content-Length or accumulated chunked size) */
	public static final int DEFAULT_MAX_BODY_SIZE = 10 * 1024 * 1024; // 10 MB

	/**
	 * The request method.
	 */
	private final HttpMethod requestMethod;
	/**
	 * The URL, optionally without protocol.
	 */
	private final String url;
	/**
	 * Encoding of parameters and body text.
	 */
	private Charset encoding = StandardCharsets.UTF_8;

	/**
	 * Connect timeout, -1 for the default.
	 */
	private int connectTimeoutMillis = -1;
	/**
	 * Read timeout, -1 for the default.
	 */
	private int readTimeoutMillis = -1;

	/**
	 * Request headers with case insensitive names.
	 */
	private final Map<String, String> headers = new CaseInsensitiveLinkedMap<>();
	/**
	 * Parameters added to the URL query.
	 */
	private final Map<String, List<Object>> urlParameters = new HashMap<>();
	/**
	 * Parameters sent as form data in the body.
	 */
	private final Map<String, List<Object>> postParameters= new HashMap<>();
	/**
	 * Body text.
	 */
	private String requestBody = null;
	/**
	 * Body stream.
	 */
	private InputStream requestBodyContentStream = null;
	/**
	 * Files sent as multipart data.
	 */
	private final List<UploadFileAttachment> uploadFileAttachments = new ArrayList<>();
	/**
	 * Stream receiving the response body.
	 */
	private OutputStream downloadStream = null;
	/**
	 * File receiving the response body.
	 */
	private File downloadFile = null;
	/**
	 * Directory or file receiving a file download.
	 */
	private File downloadTarget = null;
	/**
	 * Matrix parameters added to the URL path (";name=value").
	 */
	private final Map<String, Object> pathParameterData = new LinkedHashMap<>();
	/**
	 * Cookies sent with the request.
	 */
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

	/**
	 * File sent as part of a multipart/form-data request.
	 */
	public class UploadFileAttachment {
		/**
		 * Name of the form field.
		 */
		private String htmlInputName;
		/**
		 * Name of the file.
		 */
		private String fileName;
		/**
		 * Content of the file.
		 */
		private byte[] data;

		/**
		 * Creates a file attachment.
		 *
		 * @param htmlInputName
		 *            name of the form field
		 * @param fileName
		 *            name of the file
		 * @param data
		 *            content of the file
		 */
		public UploadFileAttachment(final String htmlInputName, final String fileName, final byte[] data) {
			super();
			this.htmlInputName = htmlInputName;
			this.fileName = fileName;
			this.data = data;
		}

		/**
		 * Returns the name of the form field.
		 *
		 * @return the name of the form field
		 */
		public String getHtmlInputName() {
			return htmlInputName;
		}

		/**
		 * Sets the name of the form field.
		 *
		 * @param htmlInputName
		 *            the name of the form field
		 * @return this attachment for chaining
		 */
		public UploadFileAttachment setHtmlInputName(final String htmlInputName) {
			this.htmlInputName = htmlInputName;
			return this;
		}

		/**
		 * Returns the name of the file.
		 *
		 * @return the name of the file
		 */
		public String getFileName() {
			return fileName;
		}

		/**
		 * Sets the name of the file.
		 *
		 * @param fileName
		 *            the name of the file
		 * @return this attachment for chaining
		 */
		public UploadFileAttachment setFileName(final String fileName) {
			this.fileName = fileName;
			return this;
		}

		/**
		 * Returns the content of the file.
		 *
		 * @return the content of the file
		 */
		public byte[] getData() {
			return data;
		}

		/**
		 * Sets the content of the file.
		 *
		 * @param data
		 *            the content of the file
		 * @return this attachment for chaining
		 */
		public UploadFileAttachment setData(final byte[] data) {
			this.data = data;
			return this;
		}
	}

	/**
	 * Creates a POST request.
	 *
	 * @param url
	 *            the URL, "https://" is added if it has no protocol
	 * @throws Exception
	 *             if the URL is blank
	 */
	public HttpRequest(final String url) throws Exception {
		this(HttpMethod.POST, url);
	}

	/**
	 * Creates a request.
	 *
	 * @param requestMethod
	 *            the method, null for GET
	 * @param url
	 *            the URL, "https://" is added if it has no protocol
	 * @throws Exception
	 *             if the URL is blank
	 */
	public HttpRequest(final HttpMethod requestMethod, final String url) throws Exception {
		if (NetworkUtilities.isBlank(url)) {
			throw new Exception("Invalid empty url");
		}
		this.requestMethod = requestMethod == null ? HttpMethod.GET : requestMethod;
		this.url = url;
	}

	/**
	 * Returns the request method.
	 *
	 * @return the method
	 */
	public HttpMethod getRequestMethod() {
		return requestMethod;
	}

	/**
	 * Returns the URL as given.
	 *
	 * @return the URL, maybe without protocol
	 */
	public String getUrl() {
		return url;
	}

	/**
	 * Returns the URL with protocol: an URL without "https://" or "http://" gets the prefix "https://".
	 *
	 * @return the URL with protocol
	 * @throws Exception
	 *             if the URL is empty
	 */
	public String getUrlWithProtocol() throws Exception {
		if (NetworkUtilities.isBlank(url)) {
			throw new Exception("Invalid empty URL for http request");
		} else if (url.toLowerCase(Locale.ROOT).startsWith(HttpConstants.SECURE_HTTP_PROTOCOL_SIGN) || url.toLowerCase(Locale.ROOT).startsWith(HttpConstants.HTTP_PROTOCOL_SIGN)) {
			return url;
		} else {
			return HttpConstants.SECURE_HTTP_PROTOCOL_SIGN + url;
		}
	}

	/**
	 * Returns the request headers.
	 *
	 * @return the modifiable headers with case insensitive names
	 */
	public Map<String, String> getHeaders() {
		return headers;
	}

	/**
	 * Sets a request header, replacing a header with the same name.
	 *
	 * @param key
	 *            the header name, case insensitive
	 * @param value
	 *            the header value
	 * @return this request for chaining
	 */
	public HttpRequest addHeader(final String key, final String value) {
		headers.put(key, value);

		return this;
	}

	/**
	 * Sets the "User-Agent" header.
	 *
	 * @param userAgent
	 *            the user agent
	 * @return this request for chaining
	 * @throws Exception
	 *             if the header is already set
	 */
	public HttpRequest addUserAgentHeader(final String userAgent) throws Exception {
		if (headers.containsKey(HttpConstants.HTTPHEADERNAME_USER_AGENT)) {
			throw new Exception("Request already contains a UserAgentHeader");
		} else {
			addHeader(HttpConstants.HTTPHEADERNAME_USER_AGENT, userAgent);

			return this;
		}
	}

	/**
	 * Sets the "Authorization" header for basic authentication. The header is not sent to other
	 * origins when following redirects.
	 *
	 * @param username
	 *            the user name
	 * @param password
	 *            the password
	 * @return this request for chaining
	 * @throws Exception
	 *             if the header is already set
	 */
	public HttpRequest addBasicAuthenticationHeader(final String username, final String password) throws Exception {
		if (headers.containsKey(HttpConstants.HTTPHEADERNAME_AUTHORIZATION)) {
			throw new Exception("Request already contains a BasicAuthenticationHeader");
		} else {
			addHeader(HttpConstants.HTTPHEADERNAME_AUTHORIZATION, HttpUtilities.createBasicAuthenticationHeaderValue(username, password));

			return this;
		}
	}

	/**
	 * Returns the parameters added to the URL query.
	 *
	 * @return the modifiable parameters, each name with its values
	 */
	public Map<String, List<Object>> getUrlParameters() {
		return urlParameters;
	}

	/**
	 * Adds a parameter to the URL query. A name may be added multiple times.
	 *
	 * @param key
	 *            the parameter name
	 * @param value
	 *            the parameter value, converted by toString()
	 * @return this request for chaining
	 */
	public HttpRequest addUrlParameter(final String key, final Object value) {
		if (!urlParameters.containsKey(key)) {
			urlParameters.put(key, new ArrayList<>());
		}
		urlParameters.get(key).add(value);

		return this;
	}

	/**
	 * Returns the parameters sent as form data in the body.
	 *
	 * @return the modifiable parameters, each name with its values
	 */
	public Map<String, List<Object>> getPostParameters() {
		return postParameters;
	}

	/**
	 * Adds a parameter sent as form data in the body. A name may be added multiple times.
	 *
	 * @param key
	 *            the parameter name
	 * @param value
	 *            the parameter value, converted by toString()
	 * @return this request for chaining
	 * @throws Exception
	 *             if a request body text or stream is set
	 */
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

	/**
	 * Returns the files sent as multipart data.
	 *
	 * @return the modifiable list of files
	 */
	public List<UploadFileAttachment> getUploadFileAttachments() {
		return uploadFileAttachments;
	}

	/**
	 * Adds a file sent as multipart/form-data.
	 *
	 * @param htmlInputName
	 *            name of the form field
	 * @param fileName
	 *            name of the file
	 * @param data
	 *            content of the file
	 * @return this request for chaining
	 * @throws Exception
	 *             if a request body text or stream is set
	 */
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

	/**
	 * Returns the stream receiving the response body.
	 *
	 * @return the stream, or null
	 */
	public OutputStream getDownloadStream() {
		return downloadStream;
	}

	/**
	 * Sets a stream receiving the response body, instead of {@link HttpResponse#getContent()}.
	 *
	 * @param downloadStream
	 *            the stream, not closed after the download
	 * @return this request for chaining
	 * @throws Exception
	 *             if a download file or target is set
	 */
	public HttpRequest setDownloadStream(final OutputStream downloadStream) throws Exception {
		if (downloadFile != null) {
			throw new Exception("DownloadFile is already set. DownloadStream cannot be set therefore");
		} else if (downloadTarget != null) {
			throw new Exception("DownloadTarget is already set. DownloadStream cannot be set therefore");
		} else {
			this.downloadStream = downloadStream;

			return this;
		}
	}

	/**
	 * Returns the file receiving the response body.
	 *
	 * @return the file, or null
	 */
	public File getDownloadFile() {
		return downloadFile;
	}

	/**
	 * Sets a file receiving the response body, instead of {@link HttpResponse#getContent()}.
	 *
	 * @param downloadFile
	 *            the file
	 * @return this request for chaining
	 * @throws Exception
	 *             if a download stream or target is set
	 */
	public HttpRequest setDownloadFile(final File downloadFile) throws Exception {
		if (downloadStream != null) {
			throw new Exception("DownloadStream is already set. DownloadFile cannot be set therefore");
		} else if (downloadTarget != null) {
			throw new Exception("DownloadTarget is already set. DownloadFile cannot be set therefore");
		} else {
			this.downloadFile = downloadFile;

			return this;
		}
	}

	/**
	 * Directory or specific file to save the response body to, but - unlike
	 * {@link #getDownloadFile()}/{@link #getDownloadStream()}, which
	 * unconditionally redirect the response body away from
	 * {@link HttpResponse#getContent()} - only if the response actually
	 * signals a file download via a "Content-Disposition: attachment" response
	 * header. A response without that header is still read and returned as
	 * normal text content even if this is set (see
	 * {@link HttpUtilities#executeHttpRequest}).
	 * <p>
	 * May point to an existing directory (the actual file name is then derived
	 * from the response, see {@link HttpUtilities}) or to a specific target
	 * file. Either way, an already existing target file is never overwritten -
	 * an ascending " (n)" suffix is appended before the file extension instead,
	 * the same way a browser handles download name collisions.
	 *
	 * @return the directory or file, or null
	 */
	public File getDownloadTarget() {
		return downloadTarget;
	}

	/**
	 * Sets the directory or file receiving a file download, see {@link #getDownloadTarget()}.
	 *
	 * @param downloadTarget
	 *            the directory or file
	 * @return this request for chaining
	 * @throws Exception
	 *             if a download stream or file is set
	 */
	public HttpRequest setDownloadTarget(final File downloadTarget) throws Exception {
		if (downloadStream != null) {
			throw new Exception("DownloadStream is already set. DownloadTarget cannot be set therefore");
		} else if (downloadFile != null) {
			throw new Exception("DownloadFile is already set. DownloadTarget cannot be set therefore");
		} else {
			this.downloadTarget = downloadTarget;

			return this;
		}
	}

	/**
	 * Returns the matrix parameters added to the URL path.
	 *
	 * @return the modifiable parameters
	 */
	public Map<String, Object> getPathParameterData() {
		return pathParameterData;
	}

	/**
	 * Adds a matrix parameter to the URL path (";name=value").
	 *
	 * @param key
	 *            the parameter name
	 * @param value
	 *            the parameter value, converted by toString()
	 * @return this request for chaining
	 */
	public HttpRequest addPathParameter(final String key, final Object value) {
		pathParameterData.put(key, value);

		return this;
	}

	/**
	 * Returns the cookies sent with the request.
	 *
	 * @return the modifiable cookies by name
	 */
	public Map<String, String> getCookieData() {
		return cookieData;
	}

	/**
	 * Adds a cookie sent with the request. Cookies are not sent to other origins when following
	 * redirects.
	 *
	 * @param name
	 *            the cookie name
	 * @param value
	 *            the cookie value
	 * @return this request for chaining
	 */
	public HttpRequest addCookieData(final String name, final String value) {
		cookieData.put(name, value);

		return this;
	}

	/**
	 * Returns the encoding of parameters and body text.
	 *
	 * @return the encoding, UTF-8 by default
	 */
	public Charset getEncoding() {
		return encoding;
	}

	/**
	 * Sets the encoding of parameters and body text.
	 *
	 * @param encoding
	 *            the encoding, null for UTF-8
	 * @return this request for chaining
	 */
	public HttpRequest setEncoding(final Charset encoding) {
		this.encoding = encoding == null ? StandardCharsets.UTF_8 : encoding;

		return this;
	}

	/**
	 * Sets the timeout for building up the connection to the server.
	 *
	 * @param connectTimeoutMillis
	 *            the timeout in milliseconds, 0 for no timeout, negative for the default
	 * @return this request for chaining
	 */
	public HttpRequest setConnectionTimeoutMillis(final int connectTimeoutMillis) {
		this.connectTimeoutMillis = connectTimeoutMillis;

		return this;
	}

	/**
	 * Returns the timeout for building up the connection.
	 *
	 * @return the timeout in milliseconds, negative for the default
	 */
	public int getConnectTimeoutMillis() {
		return connectTimeoutMillis;
	}

	/**
	 * Sets the timeout for waiting for the server's response after sending the request.
	 *
	 * @param readTimeoutMillis
	 *            the timeout in milliseconds, 0 for no timeout, negative for the default
	 * @return this request for chaining
	 */
	public HttpRequest setReadTimeoutMillis(final int readTimeoutMillis) {
		this.readTimeoutMillis = readTimeoutMillis;

		return this;
	}

	/**
	 * Returns the timeout for waiting for the response.
	 *
	 * @return the timeout in milliseconds, negative for the default
	 */
	public int getReadTimeoutMillis() {
		return readTimeoutMillis;
	}

	/**
	 * Returns the body text.
	 *
	 * @return the body text, or null
	 */
	public String getRequestBody() {
		return requestBody;
	}

	/**
	 * Returns the body stream.
	 *
	 * @return the body stream, or null
	 */
	public InputStream getRequestBodyContentStream() {
		return requestBodyContentStream;
	}

	/**
	 * Sets the body text, sent in the request encoding.
	 *
	 * @param requestBody
	 *            the body text
	 * @return this request for chaining
	 * @throws Exception
	 *             if post parameters, file uploads or a body stream are set
	 */
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

	/**
	 * Sets a stream with the body data.
	 *
	 * @param requestBodyContentStream
	 *            the body stream
	 * @return this request for chaining
	 * @throws Exception
	 *             if post parameters, file uploads or a body text are set
	 */
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

	/**
	 * Returns how redirects are followed, see {@link #setMaxRedirects(int)}.
	 *
	 * @return 0 for no redirects, negative for unlimited, positive for the maximum number of hops
	 */
	public int getMaxRedirects() {
		return maxRedirects;
	}

	/**
	 * Sets how redirects are followed. Authorization headers and cookies are not sent to other
	 * origins.
	 *
	 * @param maxRedirects
	 *            0 = do not follow redirects, negative = follow redirects without a hop limit,
	 *            positive = maximum number of redirect hops to follow before failing
	 * @return this request for chaining
	 */
	public HttpRequest setMaxRedirects(final int maxRedirects) {
		this.maxRedirects = maxRedirects;

		return this;
	}

	/** Convenience for existing callers: true means "follow up to {@link #DEFAULT_MAX_REDIRECTS} hops", false means "do not follow". Use {@link #setMaxRedirects(int)} for finer control (e.g. unlimited or a custom hop limit) */
	/**
	 * Returns whether redirects are followed at all.
	 *
	 * @return true, if redirects are followed
	 */
	public boolean isFollowRedirects() {
		return maxRedirects != 0;
	}

	/** Convenience for existing callers: true means "follow up to {@link #DEFAULT_MAX_REDIRECTS} hops", false means "do not follow". Use {@link #setMaxRedirects(int)} for finer control (e.g. unlimited or a custom hop limit) */
	/**
	 * Convenience for existing callers: true means "follow up to {@link #DEFAULT_MAX_REDIRECTS} hops",
	 * false means "do not follow". Use {@link #setMaxRedirects(int)} for finer control (e.g. unlimited
	 * or a custom hop limit).
	 *
	 * @param followRedirects
	 *            true to follow redirects
	 * @return this request for chaining
	 */
	public HttpRequest setFollowRedirects(final boolean followRedirects) {
		maxRedirects = followRedirects ? DEFAULT_MAX_REDIRECTS : 0;

		return this;
	}

	/**
	 * Returns the connection of the request currently executed.
	 *
	 * @return the connection, or null if the request is not being executed
	 */
	public HttpURLConnection getHttpURLConnection() {
		return httpURLConnection;
	}

	/**
	 * Sets the connection of the request currently executed, so it can be cancelled.
	 *
	 * @param httpURLConnection
	 *            the connection, or null
	 */
	protected void setHttpURLConnection(final HttpURLConnection httpURLConnection) {
		this.httpURLConnection = httpURLConnection;
	}

	/**
	 * Returns method and URL, e.g. "GET https://example.com".
	 */
	@Override
	public String toString() {
		return requestMethod.name() + " " + url;
	}

	/**
	 * Cancels the request currently executed by disconnecting its connection.
	 */
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
	 *
	 * <p>Header block and body are limited to {@link #DEFAULT_MAX_HEADER_SIZE} and
	 * {@link #DEFAULT_MAX_BODY_SIZE}.</p>
	 *
	 * @param inputStream
	 *            the stream to read from, e.g. of a socket
	 * @param timeoutMillis
	 *            the maximum total time for reading, greater than 0
	 * @return the request read
	 * @throws IOException
	 *             if the request is invalid, too large, or reading fails or times out
	 */
	public static HttpRequest parseHttpRequestData(final InputStream inputStream, final int timeoutMillis) throws IOException {
		return parseHttpRequestData(inputStream, timeoutMillis, DEFAULT_MAX_HEADER_SIZE, DEFAULT_MAX_BODY_SIZE);
	}

	/**
	 * Parses raw HTTP/1.x request data with custom size limits, see
	 * {@link #parseHttpRequestData(InputStream, int)}.
	 *
	 * @param inputStream
	 *            the stream to read from, e.g. of a socket
	 * @param timeoutMillis
	 *            the maximum total time for reading, greater than 0
	 * @param maxHeaderSize
	 *            the maximum size of the header block in bytes
	 * @param maxBodySize
	 *            the maximum size of the body in bytes
	 * @return the request read
	 * @throws IOException
	 *             if the request is invalid, too large, or reading fails or times out
	 */
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
			method = HttpMethod.valueOf(requestLineParts[0].toUpperCase(Locale.ROOT));
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
			try {
				for (final Map.Entry<String, List<Object>> entry : parseUrlEncodedParameters(queryString).entrySet()) {
					for (final Object value : entry.getValue()) {
						request.addUrlParameter(entry.getKey(), value);
					}
				}
			} catch (final IllegalArgumentException e) {
				// URLDecoder rejects malformed escapes like "%zz"
				throw new IOException("Invalid URL encoding in request target: '" + rawRequestTarget + "'", e);
			}
		}

		// Header lines
		for (int i = 1; i < lines.length; i++) {
			final String line = lines[i];
			if (line.isBlank()) {
				continue;
			}
			if (line.charAt(0) == ' ' || line.charAt(0) == '\t') {
				// RFC 7230 3.2.4: obsolete line folding must be rejected (or replaced) by a server
				throw new IOException("Invalid folded header line: '" + line + "'");
			}
			final int colonIndex = line.indexOf(':');
			if (colonIndex <= 0) {
				throw new IOException("Invalid header line: '" + line + "'");
			}
			final String headerName = line.substring(0, colonIndex);
			if (!headerName.equals(headerName.trim()) || headerName.indexOf(' ') >= 0 || headerName.indexOf('\t') >= 0) {
				// RFC 7230 3.2.4: whitespace between header name and colon must be rejected, because
				// intermediaries may interpret such a header differently (request smuggling)
				throw new IOException("Invalid whitespace in header name: '" + line + "'");
			}
			final String headerValue = line.substring(colonIndex + 1).trim();
			final String existingValue = request.getHeaders().get(headerName);
			if (existingValue == null) {
				request.addHeader(headerName, headerValue);
			} else if ("Cookie".equalsIgnoreCase(headerName)) {
				// RFC 6265 4.2.1: the Cookie header uses "; " as its pair separator, not RFC 7230's
				// generic ", " used below for other multi-valued headers; joining duplicate Cookie
				// header lines with ", " would corrupt the name=value pairs on later parsing.
				request.addHeader(headerName, existingValue + "; " + headerValue);
			} else {
				request.addHeader(headerName, existingValue + ", " + headerValue);
			}
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
		final boolean isChunked = transferEncoding != null && transferEncoding.toLowerCase(Locale.ROOT).contains("chunked");
		if (isChunked && request.getHeaders().get("Content-Length") != null) {
			// Presence of both headers is a classic HTTP request smuggling vector (CL.TE / TE.CL):
			// different intermediaries may pick different headers to determine the body length.
			// Per RFC 7230 3.3.3 such a message must be treated as invalid rather than silently
			// preferring one header over the other.
			throw new IOException("Invalid HTTP request: both Transfer-Encoding: chunked and Content-Length headers are present");
		}
		if (isChunked) {
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
				if (contentTypeHeader != null && contentTypeHeader.toLowerCase(Locale.ROOT).startsWith("application/x-www-form-urlencoded")) {
					final Charset bodyCharset = determineCharset(contentTypeHeader, request.getEncoding());
					final String bodyString = new String(body, bodyCharset);
					for (final Map.Entry<String, List<Object>> entry : parseUrlEncodedParameters(bodyString).entrySet()) {
						for (final Object value : entry.getValue()) {
							request.addPostParameter(entry.getKey(), value);
						}
					}
				} else if (contentTypeHeader != null && contentTypeHeader.toLowerCase(Locale.ROOT).startsWith("multipart/form-data")) {
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
			// Compared by subtraction, because "result.size() + chunkSize" can overflow for huge chunk sizes
			if (chunkSize > maxBodySize - result.size()) {
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
		final int charsetIndex = contentTypeHeader.toLowerCase(Locale.ROOT).indexOf("charset=");
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
			if (trimmedPart.toLowerCase(Locale.ROOT).startsWith("boundary=")) {
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
				// Quoted values may contain ';', e.g. filename="a;b.txt"
				for (final String segment : splitHeaderParameters(headerValue)) {
					final String trimmedSegment = segment.trim();
					final String lowerCaseSegment = trimmedSegment.toLowerCase(Locale.ROOT);
					if (lowerCaseSegment.startsWith("name=")) {
						name = unescapeMultipartHeaderValue(stripQuotes(trimmedSegment.substring("name=".length())));
					} else if (lowerCaseSegment.startsWith("filename=")) {
						fileName = unescapeMultipartHeaderValue(stripQuotes(trimmedSegment.substring("filename=".length())));
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

	/**
	 * Reverses the escaping applied by {@code HttpUtilities.escapeMultipartHeaderValue} (backslash
	 * and double-quote escaped per RFC 7578 4.2) when writing name="..."/filename="..." parameters,
	 * so that values round-trip correctly instead of retaining the literal backslash-escapes.
	 */
	private static String unescapeMultipartHeaderValue(final String value) {
		if (value == null || value.indexOf('\\') < 0) {
			return value;
		}
		final StringBuilder result = new StringBuilder(value.length());
		for (int i = 0; i < value.length(); i++) {
			final char c = value.charAt(i);
			if (c == '\\' && i + 1 < value.length()) {
				result.append(value.charAt(++i));
			} else {
				result.append(c);
			}
		}
		return result.toString();
	}

	/**
	 * Splits header parameters at ';', ignoring ';' within double quotes (with backslash escapes).
	 *
	 * @param headerValue
	 *            the header value
	 * @return the parameter segments
	 */
	private static List<String> splitHeaderParameters(final String headerValue) {
		final List<String> segments = new ArrayList<>();
		final StringBuilder segment = new StringBuilder();
		boolean inQuotes = false;
		for (int i = 0; i < headerValue.length(); i++) {
			final char c = headerValue.charAt(i);
			if (inQuotes && c == '\\' && i + 1 < headerValue.length()) {
				segment.append(c).append(headerValue.charAt(++i));
			} else if (c == '"') {
				inQuotes = !inQuotes;
				segment.append(c);
			} else if (c == ';' && !inQuotes) {
				segments.add(segment.toString());
				segment.setLength(0);
			} else {
				segment.append(c);
			}
		}
		segments.add(segment.toString());
		return segments;
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
