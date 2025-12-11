package de.soderer.network;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class HttpRequest {
	public static final String SECURE_HTTP_PROTOCOL_SIGN = "https://";
	public static final String HTTP_PROTOCOL_SIGN = "http://";

	public static final String HEADER_NAME_BASIC_AUTHENTICATION = "Authorization";
	public static final String HEADER_NAME_USER_AGENT = "User-Agent";
	public static final String HEADER_NAME_DOWNLOAD_COOKIE = "Set-Cookie";
	public static final String HEADER_NAME_UPLOAD_COOKIE = "Cookie";

	public enum HttpMethod {
		GET,
		HEAD,
		POST,
		PUT,
		DELETE,
		CONNECT,
		OPTIONS,
		TRACE,
		PATCH
	}

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

	private boolean followRedirects = false;

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
		} else if (url.toLowerCase().startsWith(SECURE_HTTP_PROTOCOL_SIGN) || url.toLowerCase().startsWith(HTTP_PROTOCOL_SIGN)) {
			return url;
		} else {
			return SECURE_HTTP_PROTOCOL_SIGN + url;
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
		if (headers.containsKey(HEADER_NAME_USER_AGENT)) {
			throw new Exception("Request already contains a UserAgentHeader");
		} else {
			addHeader(HttpRequest.HEADER_NAME_USER_AGENT, userAgent);

			return this;
		}
	}

	public HttpRequest addBasicAuthenticationHeader(final String username, final String password) throws Exception {
		if (headers.containsKey(HEADER_NAME_BASIC_AUTHENTICATION)) {
			throw new Exception("Request already contains a BasicAuthenticationHeader");
		} else {
			addHeader(HttpRequest.HEADER_NAME_BASIC_AUTHENTICATION, HttpUtilities.createBasicAuthenticationHeaderValue(username, password));

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
			throw new Exception("UploadFileAttachments are already set. RequestBody cannot be set therefore");
		} else {
			this.requestBodyContentStream = requestBodyContentStream;

			return this;
		}
	}

	public boolean isFollowRedirects() {
		return followRedirects;
	}

	public HttpRequest setFollowRedirects(final boolean followRedirects) {
		this.followRedirects = followRedirects;

		return this;
	}

	@Override
	public String toString() {
		return requestMethod.name() + " " + url;
	}

	public static HttpRequest parseHttpRequestData(final InputStream inputStream, final int timeoutMillis) throws IOException {

		//		GET /abc?b=10&c=11 HTTP/1.1
		//		Host: localhost:8080
		//		User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0
		//		Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
		//		Accept-Language: de,en-US;q=0.7,en;q=0.3
		//		Accept-Encoding: gzip, deflate, br, zstd
		//		DNT: 1
		//		Sec-GPC: 1
		//		Connection: keep-alive
		//		Upgrade-Insecure-Requests: 1
		//		Sec-Fetch-Dest: document
		//		Sec-Fetch-Mode: navigate
		//		Sec-Fetch-Site: none
		//		Sec-Fetch-User: ?1
		//		Priority: u=0, i
		//		Content-type: application/x-www-form-urlencoded
		//		Content-Length: 25

		try (final BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
			String requestData = "";
			try {
				int nextCharInt;
				while ((nextCharInt = reader.read()) != -1) {
					requestData += (char) nextCharInt;
					if (requestData.endsWith("\r\n\r\n")) {
						requestData = requestData.trim();
						break;
					}
				}
			} catch (final IOException ex) {
				System.err.println(ex.getMessage());
			}
			return null;
		}
	}
}