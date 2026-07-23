package de.soderer.utilities;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import org.junit.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import de.soderer.network.HttpMethod;
import de.soderer.network.HttpRequest;
import de.soderer.network.HttpResponse;
import de.soderer.network.HttpUtilities;

/**
 * End-to-end tests against real (local, ephemeral-port) HTTP servers, covering the redirect
 * fixes in HttpUtilities.executeHttpRequest: cross-origin credential stripping, relative
 * Location resolution, HTTP-semantics-correct method/body handling for 303 vs 307.
 */
@SuppressWarnings("static-method")
public class HttpUtilitiesRedirectTest {
	private static HttpServer startServer(final HttpHandler handler) throws IOException {
		final HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
		server.createContext("/", handler);
		server.setExecutor(null);
		server.start();
		return server;
	}

	private static void respond(final HttpExchange exchange, final int statusCode, final String body) throws IOException {
		final byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
		exchange.sendResponseHeaders(statusCode, bodyBytes.length);
		try (OutputStream responseBody = exchange.getResponseBody()) {
			responseBody.write(bodyBytes);
		}
	}

	@Test
	public void testSameOriginRedirectKeepsCookieAndAuthorization() throws Exception {
		final HttpServer server = startServer(exchange -> {
			final String path = exchange.getRequestURI().getPath();
			if ("/start".equals(path)) {
				exchange.getResponseHeaders().add("Location", "/redirected");
				exchange.sendResponseHeaders(302, -1);
				exchange.close();
			} else {
				final String cookieHeader = exchange.getRequestHeaders().getFirst("Cookie");
				final boolean hasCookie = cookieHeader != null && cookieHeader.contains("sessionId=abc123");
				final boolean hasAuth = exchange.getRequestHeaders().getFirst("Authorization") != null;
				respond(exchange, 200, hasCookie && hasAuth ? "OK" : "MISSING");
			}
		});

		try {
			final int port = server.getAddress().getPort();
			final HttpRequest request = new HttpRequest(HttpMethod.GET, "http://localhost:" + port + "/start");
			request.addCookieData("sessionId", "abc123");
			request.addHeader("Authorization", "Bearer test-token");
			request.setMaxRedirects(5);

			final HttpResponse response = HttpUtilities.executeHttpRequest(request);

			assertEquals(200, response.getHttpCode());
			assertEquals("OK", response.getContent());
		} finally {
			server.stop(0);
		}
	}

	@Test
	public void testCrossOriginRedirectStripsCookieAndAuthorization() throws Exception {
		final HttpServer targetServer = startServer(exchange -> {
			final boolean hasCookie = exchange.getRequestHeaders().getFirst("Cookie") != null;
			final boolean hasAuth = exchange.getRequestHeaders().getFirst("Authorization") != null;
			respond(exchange, 200, hasCookie || hasAuth ? "LEAKED" : "CLEAN");
		});

		try {
			final int targetPort = targetServer.getAddress().getPort();

			final HttpServer startServer = startServer(exchange -> {
				exchange.getResponseHeaders().add("Location", "http://localhost:" + targetPort + "/target");
				exchange.sendResponseHeaders(302, -1);
				exchange.close();
			});

			try {
				final int startPort = startServer.getAddress().getPort();
				final HttpRequest request = new HttpRequest(HttpMethod.GET, "http://localhost:" + startPort + "/start");
				request.addCookieData("sessionId", "abc123");
				request.addHeader("Authorization", "Bearer test-token");
				request.setMaxRedirects(5);

				final HttpResponse response = HttpUtilities.executeHttpRequest(request);

				assertEquals(200, response.getHttpCode());
				assertEquals("CLEAN", response.getContent());
			} finally {
				startServer.stop(0);
			}
		} finally {
			targetServer.stop(0);
		}
	}

	@Test
	public void test303AlwaysDowngradesToGetAndDropsBody() throws Exception {
		final HttpServer server = startServer(exchange -> {
			final String path = exchange.getRequestURI().getPath();
			if ("/start".equals(path)) {
				exchange.getRequestBody().readAllBytes();
				exchange.getResponseHeaders().add("Location", "/target");
				exchange.sendResponseHeaders(303, -1);
				exchange.close();
			} else {
				final byte[] receivedBody = exchange.getRequestBody().readAllBytes();
				final boolean isGetWithNoBody = "GET".equals(exchange.getRequestMethod()) && receivedBody.length == 0;
				respond(exchange, 200, isGetWithNoBody ? "OK" : "UNEXPECTED");
			}
		});

		try {
			final int port = server.getAddress().getPort();
			final HttpRequest request = new HttpRequest(HttpMethod.POST, "http://localhost:" + port + "/start");
			request.setRequestBody("original-body");
			request.setMaxRedirects(5);

			final HttpResponse response = HttpUtilities.executeHttpRequest(request);

			assertEquals(200, response.getHttpCode());
			assertEquals("OK", response.getContent());
		} finally {
			server.stop(0);
		}
	}

	@Test
	public void test307PreservesMethodAndBody() throws Exception {
		final HttpServer server = startServer(exchange -> {
			final String path = exchange.getRequestURI().getPath();
			if ("/start".equals(path)) {
				exchange.getRequestBody().readAllBytes();
				exchange.getResponseHeaders().add("Location", "/target");
				exchange.sendResponseHeaders(307, -1);
				exchange.close();
			} else {
				final byte[] receivedBody = exchange.getRequestBody().readAllBytes();
				final String receivedText = new String(receivedBody, StandardCharsets.UTF_8);
				final boolean isPostWithOriginalBody = "POST".equals(exchange.getRequestMethod())
						&& "original-body".equals(receivedText);
				respond(exchange, 200, isPostWithOriginalBody ? "OK" : "UNEXPECTED");
			}
		});

		try {
			final int port = server.getAddress().getPort();
			final HttpRequest request = new HttpRequest(HttpMethod.POST, "http://localhost:" + port + "/start");
			request.setRequestBody("original-body");
			request.setMaxRedirects(5);

			final HttpResponse response = HttpUtilities.executeHttpRequest(request);

			assertEquals(200, response.getHttpCode());
			assertEquals("OK", response.getContent());
		} finally {
			server.stop(0);
		}
	}
}
