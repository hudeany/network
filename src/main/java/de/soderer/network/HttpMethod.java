package de.soderer.network;

public enum HttpMethod {
	GET,
	HEAD,
	POST,
	PUT,
	DELETE,
	CONNECT,
	OPTIONS,
	TRACE,
	PATCH;

	public static HttpMethod getHttpMethodByName(final String httpMethodName) throws Exception {
		for (final HttpMethod httpMethod : HttpMethod.values()) {
			if (httpMethod.name().equalsIgnoreCase(httpMethodName)) {
				return httpMethod;
			}
		}
		throw new Exception("Unknown HttpMethod name: '" + httpMethodName + "'");
	}
}
