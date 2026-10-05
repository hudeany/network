package de.soderer.network;

import java.util.Collections;
import java.util.Map;
import java.util.Map.Entry;

/**
 * Response of an HTTP request executed by {@link HttpUtilities#executeHttpRequest(HttpRequest)}.
 * <p>
 * Headers and cookies are unmodifiable. If the response body was saved to a file, the content is
 * null and {@link #getDownloadedFilePath()} names the file.
 * </p>
 */
public class HttpResponse {
	/**
	 * IP address of the server.
	 */
	private final String ipAddress;
	/**
	 * HTTP status code.
	 */
	private final int httpCode;
	/**
	 * HTTP status message.
	 */
	private final String httpCodeMessage;
	/**
	 * Response body as text.
	 */
	private final String content;
	/**
	 * Value of the "Content-Type" header.
	 */
	private final String contentType;
	/**
	 * Response headers.
	 */
	private final Map<String, String> headers;
	/**
	 * Cookies set by the response.
	 */
	private final Map<String, String> cookieData;
	/**
	 * Number of followed redirects.
	 */
	private final int redirectCount;
	/**
	 * URL of the last redirect target.
	 */
	private final String finalUrl;
	/**
	 * True, if credentials were withheld on a cross-origin redirect.
	 */
	private final boolean credentialsDroppedOnRedirect;
	/**
	 * Path of the file the body was saved to.
	 */
	private final String downloadedFilePath;

	/**
	 * Creates a response without redirect information.
	 *
	 * @param ipAddress
	 *            IP address of the server, may be null
	 * @param httpCode
	 *            HTTP status code
	 * @param httpCodeMessage
	 *            HTTP status message
	 * @param content
	 *            response body as text, null if it was saved to a file
	 * @param contentType
	 *            value of the "Content-Type" header
	 * @param headers
	 *            response headers, may be null
	 * @param cookieData
	 *            cookies set by the response, may be null
	 */
	public HttpResponse(final String ipAddress, final int httpCode, final String httpCodeMessage, final String content, final String contentType, final Map<String, String> headers, final Map<String, String> cookieData) {
		this(ipAddress, httpCode, httpCodeMessage, content, contentType, headers, cookieData, 0, null, false);
	}

	/**
	 * Creates a response without IP address and redirect information.
	 *
	 * @param httpCode
	 *            HTTP status code
	 * @param httpCodeMessage
	 *            HTTP status message
	 * @param content
	 *            response body as text, null if it was saved to a file
	 * @param contentType
	 *            value of the "Content-Type" header
	 * @param headers
	 *            response headers, may be null
	 * @param cookieData
	 *            cookies set by the response, may be null
	 */
	public HttpResponse(final int httpCode, final String httpCodeMessage, final String content, final String contentType, final Map<String, String> headers, final Map<String, String> cookieData) {
		this(null, httpCode, httpCodeMessage, content, contentType, headers, cookieData, 0, null, false);
	}

	/**
	 * Creates a response.
	 *
	 * @param ipAddress
	 *            IP address of the server, may be null
	 * @param httpCode
	 *            HTTP status code
	 * @param httpCodeMessage
	 *            HTTP status message
	 * @param content
	 *            response body as text, null if it was saved to a file
	 * @param contentType
	 *            value of the "Content-Type" header
	 * @param headers
	 *            response headers, may be null
	 * @param cookieData
	 *            cookies set by the response, may be null
	 * @param redirectCount
	 *            number of redirect hops that were followed to arrive at this response (0 if none)
	 * @param finalUrl
	 *            the URL this response actually came from, i.e. the last URL in the redirect chain (null if no redirect was followed)
	 * @param credentialsDroppedOnRedirect
	 *            true if an Authorization header and/or cookies were withheld at least once while
	 *            following a redirect to a different origin (see {@link HttpUtilities#executeHttpRequest(HttpRequest)})
	 */
	public HttpResponse(final String ipAddress, final int httpCode, final String httpCodeMessage, final String content, final String contentType, final Map<String, String> headers, final Map<String, String> cookieData,
			final int redirectCount, final String finalUrl, final boolean credentialsDroppedOnRedirect) {
		this(ipAddress, httpCode, httpCodeMessage, content, contentType, headers, cookieData, redirectCount, finalUrl, credentialsDroppedOnRedirect, null);
	}

	/**
	 * Creates a response.
	 *
	 * @param ipAddress
	 *            IP address of the server, may be null
	 * @param httpCode
	 *            HTTP status code
	 * @param httpCodeMessage
	 *            HTTP status message
	 * @param content
	 *            response body as text, null if it was saved to a file
	 * @param contentType
	 *            value of the "Content-Type" header
	 * @param headers
	 *            response headers, may be null
	 * @param cookieData
	 *            cookies set by the response, may be null
	 * @param redirectCount
	 *            number of redirect hops that were followed to arrive at this response (0 if none)
	 * @param finalUrl
	 *            the URL this response actually came from, i.e. the last URL in the redirect chain (null if no redirect was followed)
	 * @param credentialsDroppedOnRedirect
	 *            true if an Authorization header and/or cookies were withheld at least once while
	 *            following a redirect to a different origin (see {@link HttpUtilities#executeHttpRequest(HttpRequest)})
	 * @param downloadedFilePath
	 *            absolute path the response body was actually saved to (see {@link HttpRequest#getDownloadFile()}/
	 *            {@link HttpRequest#getDownloadTarget()}), or null if the body was not saved to a file
	 */
	public HttpResponse(final String ipAddress, final int httpCode, final String httpCodeMessage, final String content, final String contentType, final Map<String, String> headers, final Map<String, String> cookieData,
			final int redirectCount, final String finalUrl, final boolean credentialsDroppedOnRedirect, final String downloadedFilePath) {
		this.ipAddress = ipAddress;
		this.httpCode = httpCode;
		this.httpCodeMessage = httpCodeMessage;
		this.content = content;
		this.contentType = contentType;
		this.headers = headers == null ? null : Collections.unmodifiableMap(headers);
		this.cookieData = cookieData == null ? null : Collections.unmodifiableMap(cookieData);
		this.redirectCount = redirectCount;
		this.finalUrl = finalUrl;
		this.credentialsDroppedOnRedirect = credentialsDroppedOnRedirect;
		this.downloadedFilePath = downloadedFilePath;
	}

	/**
	 * Returns the IP address of the server.
	 *
	 * @return the IP address, or null if unknown
	 */
	public String getIpAddress() {
		return ipAddress;
	}

	/**
	 * Returns the HTTP status code.
	 *
	 * @return the status code, e.g. 200
	 */
	public int getHttpCode() {
		return httpCode;
	}

	/**
	 * Returns the status message of the response.
	 *
	 * @return the status message, e.g. "Not Found", or null
	 */
	public String getHttpCodeMessage() {
		return httpCodeMessage;
	}

	/**
	 * Returns the response body as text.
	 *
	 * @return the body, or null if it was saved to a file or stream
	 */
	public String getContent() {
		return content;
	}

	/**
	 * Returns the value of the "Content-Type" header.
	 *
	 * @return the content type, or null
	 */
	public String getContentType() {
		return contentType;
	}

	/**
	 * Returns the response headers.
	 *
	 * @return the unmodifiable headers, may be null
	 */
	public Map<String, String> getHeaders() {
		return headers;
	}

	/**
	 * Returns the cookies set by the response.
	 *
	 * @return the unmodifiable cookies by name, may be null
	 */
	public Map<String, String> getCookies() {
		return cookieData;
	}

	/** Number of redirect hops that were followed to arrive at this response (0 if none) */
	/**
	 * Number of redirect hops that were followed to arrive at this response (0 if none)
	 *
	 * @return the number of redirects, 0 if none
	 */
	public int getRedirectCount() {
		return redirectCount;
	}

	/** The URL this response actually came from, i.e. the last URL in the redirect chain (null if no redirect was followed) */
	/**
	 * The URL this response actually came from, i.e. the last URL in the redirect chain (null if no redirect was followed)
	 *
	 * @return the URL, or null if no redirect was followed
	 */
	public String getFinalUrl() {
		return finalUrl;
	}

	/** True if an Authorization header and/or cookies were withheld at least once while following a redirect to a different origin */
	/**
	 * True if an Authorization header and/or cookies were withheld at least once while following a redirect to a different origin
	 *
	 * @return true, if credentials were withheld
	 */
	public boolean isCredentialsDroppedOnRedirect() {
		return credentialsDroppedOnRedirect;
	}

	/** Absolute path the response body was actually saved to, or null if the body was not saved to a file */
	/**
	 * Absolute path the response body was actually saved to, or null if the body was not saved to a file
	 *
	 * @return the absolute file path, or null
	 */
	public String getDownloadedFilePath() {
		return downloadedFilePath;
	}

	/**
	 * Returns a multiline description of the response for logging, including headers and content.
	 */
	@Override
	public String toString() {
		String returnText = "HttpCode: " + httpCode + (NetworkUtilities.isNotEmpty(httpCodeMessage) ? " (" + httpCodeMessage + ")" : "") + "\n";
		if (redirectCount > 0) {
			returnText += "Redirects: " + redirectCount + " -> " + finalUrl + (credentialsDroppedOnRedirect ? " (credentials dropped on cross-origin redirect)" : "") + "\n";
		}
		if (headers != null && headers.size() > 0) {
			returnText += "HttpHeaders:\n";
			for (final Entry<String, String> entry : headers.entrySet()) {
				returnText += "\t" + entry.getKey() + ": " + entry.getValue() + "\n";
			}
		}
		if (cookieData != null && cookieData.size() > 0) {
			returnText += "HttpCookies:\n";
			for (final Entry<String, String> entry : cookieData.entrySet()) {
				returnText += "\t" + entry.getKey() + ": " + entry.getValue() + "\n";
			}
		}
		returnText += "ContentType: " + contentType + "\n";
		returnText += "Content: \n" + content + "\n";
		return returnText;
	}
}
