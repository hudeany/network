package de.soderer.network;

public enum HttpContentType {
	HtmlForm("application/x-www-form-urlencoded"),
	MultipartForm("multipart/form-data"),
	Json("application/json"),
	Yaml("application/yaml"),
	Zip("application/zip"),
	Binary("application/octet-stream"),
	Html("text/html"),
	Text("text/plain");

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
