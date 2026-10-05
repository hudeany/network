package de.soderer.network;

/**
 * Names of common HTTP headers and other HTTP related constants.
 */
public class HttpConstants {
	/**
	 * Constants class, not to be instantiated.
	 */
	private HttpConstants() {
	}

	/**
	 * Header "Content-Length".
	 */
	public static final String HTTPHEADERNAME_CONTENTLENGTH = "Content-Length";
	/**
	 * Header "Content-Type".
	 */
	public static final String HTTPHEADERNAME_CONTENTTYPE = "Content-Type";
	/**
	 * Header "Content-Disposition".
	 */
	public static final String HTTPHEADERNAME_DISPOSITION  = "Content-Disposition";
	/**
	 * Header "Accept".
	 */
	public static final String HTTPHEADERNAME_ACCEPT = "Accept";

	/**
	 * Header "Authorization".
	 */
	public static final String HTTPHEADERNAME_AUTHORIZATION = "Authorization";
	/**
	 * Header "Proxy-Authorization".
	 */
	public static final String HTTPHEADERNAME_PROXY_AUTHORIZATION = "Proxy-Authorization";

	/**
	 * Scheme of a bearer token in the "Authorization" header.
	 */
	public static final String AUTHORIZATIONHEADER_START_BEARER = "Bearer";
	/**
	 * Scheme of basic authentication in the "Authorization" header.
	 */
	public static final String AUTHORIZATIONHEADER_START_BASIC = "Basic";

	/**
	 * URL prefix of HTTPS.
	 */
	public static final String SECURE_HTTP_PROTOCOL_SIGN = "https://";
	/**
	 * URL prefix of HTTP.
	 */
	public static final String HTTP_PROTOCOL_SIGN = "http://";

	/**
	 * Header "User-Agent".
	 */
	public static final String HTTPHEADERNAME_USER_AGENT = "User-Agent";

	/**
	 * Request header "Cookie".
	 */
	public static final String HTTPHEADERNAME_COOKIE = "Cookie";
	/**
	 * Response header "Set-Cookie".
	 */
	public static final String HTTPHEADERNAME_DOWNLOAD_COOKIE = "Set-Cookie";
}
