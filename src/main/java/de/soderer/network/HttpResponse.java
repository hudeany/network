package de.soderer.network;

import java.util.Collections;
import java.util.Map;
import java.util.Map.Entry;

public class HttpResponse {
	private final String ipAddress;
	private final int httpCode;
	private final String httpCodeMessage;
	private final String content;
	private final String contentType;
	private final Map<String, String> headers;
	private final Map<String, String> cookieData;
	private final int redirectCount;
	private final String finalUrl;
	private final boolean credentialsDroppedOnRedirect;
	private final String downloadedFilePath;

	public HttpResponse(final String ipAddress, final int httpCode, final String httpCodeMessage, final String content, final String contentType, final Map<String, String> headers, final Map<String, String> cookieData) {
		this(ipAddress, httpCode, httpCodeMessage, content, contentType, headers, cookieData, 0, null, false);
	}

	public HttpResponse(final int httpCode, final String httpCodeMessage, final String content, final String contentType, final Map<String, String> headers, final Map<String, String> cookieData) {
		this(null, httpCode, httpCodeMessage, content, contentType, headers, cookieData, 0, null, false);
	}

	/**
	 * @param redirectCount number of redirect hops that were followed to arrive at this response (0 if none)
	 * @param finalUrl the URL this response actually came from, i.e. the last URL in the redirect chain (null if no redirect was followed)
	 * @param credentialsDroppedOnRedirect true if an Authorization header and/or cookies were withheld at least once while
	 *        following a redirect to a different origin (see {@link HttpUtilities#executeHttpRequest})
	 */
	public HttpResponse(final String ipAddress, final int httpCode, final String httpCodeMessage, final String content, final String contentType, final Map<String, String> headers, final Map<String, String> cookieData,
			final int redirectCount, final String finalUrl, final boolean credentialsDroppedOnRedirect) {
		this(ipAddress, httpCode, httpCodeMessage, content, contentType, headers, cookieData, redirectCount, finalUrl, credentialsDroppedOnRedirect, null);
	}

	/**
	 * @param redirectCount number of redirect hops that were followed to arrive at this response (0 if none)
	 * @param finalUrl the URL this response actually came from, i.e. the last URL in the redirect chain (null if no redirect was followed)
	 * @param credentialsDroppedOnRedirect true if an Authorization header and/or cookies were withheld at least once while
	 *        following a redirect to a different origin (see {@link HttpUtilities#executeHttpRequest})
	 * @param downloadedFilePath absolute path the response body was actually saved to (see {@link HttpRequest#getDownloadFile()}/
	 *        {@link HttpRequest#getDownloadTarget()}), or null if the body was not saved to a file
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

	public String getIpAddress() {
		return ipAddress;
	}

	public int getHttpCode() {
		return httpCode;
	}

	public String getContent() {
		return content;
	}

	public String getContentType() {
		return contentType;
	}

	public Map<String, String> getHeaders() {
		return headers;
	}

	public Map<String, String> getCookies() {
		return cookieData;
	}

	/** Number of redirect hops that were followed to arrive at this response (0 if none) */
	public int getRedirectCount() {
		return redirectCount;
	}

	/** The URL this response actually came from, i.e. the last URL in the redirect chain (null if no redirect was followed) */
	public String getFinalUrl() {
		return finalUrl;
	}

	/** True if an Authorization header and/or cookies were withheld at least once while following a redirect to a different origin */
	public boolean isCredentialsDroppedOnRedirect() {
		return credentialsDroppedOnRedirect;
	}

	/** Absolute path the response body was actually saved to, or null if the body was not saved to a file */
	public String getDownloadedFilePath() {
		return downloadedFilePath;
	}

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
