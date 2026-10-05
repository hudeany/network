package de.soderer.network;

import java.util.Locale;

/**
 * Common content types (MIME types) of HTTP data.
 */
public enum HttpContentType {
	/** application/x-www-form-urlencoded */
	HtmlForm("application/x-www-form-urlencoded"),

	/** multipart/form-data */
	MultipartForm("multipart/form-data"),

	/** application/json */
	Json("application/json"),

	/** application/xml */
	Xml("application/xml"),

	/** application/yaml */
	Yaml("application/yaml"),

	/** application/zip */
	Zip("application/zip"),

	/** application/octet-stream */
	Binary("application/octet-stream"),

	/** text/html */
	Html("text/html"),

	/** text/plain */
	Text("text/plain"),

	/**
	 * text/json<br />
	 * Used to tell browsers to display data rather then download it to a file*/
	TextJson("text/json"),

	/**
	 * text/yaml<br />
	 * Used to tell browsers to display data rather then download it to a file*/
	TextYaml("text/yaml"),

	/**
	 * text/xml<br />
	 * Used to tell browsers to display data rather then download it to a file*/
	TextXml("text/xml");

	/**
	 * The MIME type.
	 */
	private final String stringRepresentation;

	/**
	 * Creates a content type.
	 *
	 * @param stringRepresentation
	 *            the MIME type
	 */
	HttpContentType(final String stringRepresentation) {
		this.stringRepresentation = stringRepresentation;
	}

	/**
	 * Returns the content type of a "Content-Type" header value, ignoring case and parameters like
	 * "; charset=UTF-8".
	 *
	 * @param httpContentTypeString
	 *            the header value, e.g. "application/json; charset=UTF-8"
	 * @return the content type
	 * @throws Exception
	 *             if the value is null or the MIME type is unknown
	 */
	public static HttpContentType getHttpContentTypeByName(final String httpContentTypeString) throws Exception {
		if (httpContentTypeString != null) {
			// Parameters like "; charset=UTF-8" are ignored, also with whitespace before the ';'
			final String mimeType = httpContentTypeString.split(";", 2)[0].trim();
			for (final HttpContentType httpContentType : HttpContentType.values()) {
				if (httpContentType.stringRepresentation.equalsIgnoreCase(mimeType)) {
					return httpContentType;
				}
			}
		}
		throw new Exception("Unknown HttpContentType: '" + httpContentTypeString + "'");
	}

	/**
	 * Returns the MIME type.
	 *
	 * @return the MIME type, e.g. "application/json"
	 */
	public String getStringRepresentation() {
		return stringRepresentation;
	}

	/**
	 * Returns the MIME type.
	 */
	@Override
	public String toString() {
		return stringRepresentation;
	}
}
