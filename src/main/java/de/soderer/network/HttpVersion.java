package de.soderer.network;

/**
 * HTTP protocol version: requested by a {@link HttpRequest} and actually used by a {@link HttpResponse}.
 */
public enum HttpVersion {
	/**
	 * HTTP/1.0. Cannot be requested, only reported by {@link HttpResponse#getHttpVersion()} if an old
	 * server answers with HTTP/1.0.
	 */
	HTTP_1_0("HTTP/1.0"),

	/**
	 * HTTP/1.1, sent via {@link java.net.HttpURLConnection}.
	 */
	HTTP_1_1("HTTP/1.1"),

	/**
	 * HTTP/2, sent via {@link java.net.http.HttpClient}. For "https" the version is negotiated via TLS
	 * ALPN, for "http" an "h2c" upgrade is tried. If the server does not support HTTP/2, HTTP/1.1 is used.
	 */
	HTTP_2("HTTP/2");

	/**
	 * Protocol name as used in HTTP, e.g. "HTTP/1.1".
	 */
	private final String protocolName;

	HttpVersion(final String protocolName) {
		this.protocolName = protocolName;
	}

	/**
	 * Returns the protocol name as used in HTTP.
	 *
	 * @return the protocol name, e.g. "HTTP/1.1"
	 */
	public String getProtocolName() {
		return protocolName;
	}
}
