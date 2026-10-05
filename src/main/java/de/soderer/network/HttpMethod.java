package de.soderer.network;

/**
 * HTTP request methods.
 */
public enum HttpMethod {
	/**
	 * Request a resource.
	 */
	GET,
	/**
	 * Request only the headers of a resource.
	 */
	HEAD,
	/**
	 * Send data to a resource.
	 */
	POST,
	/**
	 * Create or replace a resource.
	 */
	PUT,
	/**
	 * Delete a resource.
	 */
	DELETE,
	/**
	 * Open a tunnel, e.g. through a proxy.
	 */
	CONNECT,
	/**
	 * Request the supported communication options.
	 */
	OPTIONS,
	/**
	 * Echo the request for diagnostics.
	 */
	TRACE,
	/**
	 * Partially change a resource.
	 */
	PATCH;

	/**
	 * Returns the method with the given name, ignoring case.
	 *
	 * @param httpMethodName
	 *            the name, e.g. "get"
	 * @return the method
	 * @throws Exception
	 *             if the name is unknown
	 */
	public static HttpMethod getHttpMethodByName(final String httpMethodName) throws Exception {
		for (final HttpMethod httpMethod : HttpMethod.values()) {
			if (httpMethod.name().equalsIgnoreCase(httpMethodName)) {
				return httpMethod;
			}
		}
		throw new Exception("Unknown HttpMethod name: '" + httpMethodName + "'");
	}
}
