package de.soderer.network;

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

	private final String stringRepresentation;

	HttpContentType(final String stringRepresentation) {
		this.stringRepresentation = stringRepresentation;
	}

	public static HttpContentType getHttpContentTypeByName(final String httpContentTypeString) throws Exception {
		for (final HttpContentType httpContentType : HttpContentType.values()) {
			if (httpContentType.stringRepresentation.equalsIgnoreCase(httpContentTypeString)) {
				return httpContentType;
			}
		}
		throw new Exception("Unknown HttpContentType: '" + httpContentTypeString + "'");
	}

	public String getStringRepresentation() {
		return stringRepresentation;
	}

	@Override
	public String toString() {
		return stringRepresentation;
	}
}
