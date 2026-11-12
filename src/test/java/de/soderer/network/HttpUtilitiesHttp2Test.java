package de.soderer.network;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import javax.net.ssl.TrustManager;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import de.soderer.network.trustmanager.PemFileTrustManager;

/**
 * Tests of {@link HttpUtilities} with a requested HTTP version, against a local server that speaks
 * HTTP/2 (via TLS ALPN or cleartext upgrade) or only HTTP/1.1 (fallback).
 */
@SuppressWarnings("static-method")
public class HttpUtilitiesHttp2Test {
	private TestHttp2Server server;

	@AfterEach
	public void stopServer() {
		if (server != null) {
			server.close();
			assertTrue(server.getErrors().isEmpty(), "Server side errors: " + server.getErrors());
		}
	}

	private static Function<TestHttp2Server.Request, TestHttp2Server.Response> respondWith(final String body) {
		return request -> new TestHttp2Server.Response(200, body);
	}

	private static Function<TestHttp2Server.Request, TestHttp2Server.Response> echoBody() {
		return request -> new TestHttp2Server.Response(200, request.bodyAsString());
	}

	private String startTlsServer(final boolean http2Enabled, final Function<TestHttp2Server.Request, TestHttp2Server.Response> handler) throws Exception {
		server = TestHttp2Server.startTls(TestTlsSupport.getLocalhostKeystoreFile(), http2Enabled, handler);
		return server.getBaseUrl() + "/";
	}

	private String startCleartextServer(final boolean http2Enabled, final Function<TestHttp2Server.Request, TestHttp2Server.Response> handler) throws Exception {
		server = TestHttp2Server.startCleartext(http2Enabled, handler);
		return server.getBaseUrl() + "/";
	}

	private static HttpResponse executeWithLocalhostTrust(final HttpRequest request) throws Exception {
		return HttpUtilities.executeHttpRequest(request, Proxy.NO_PROXY, new PemFileTrustManager(TestTlsSupport.getLocalhostPemFile()), false);
	}

	@Test
	public void testHttp2ViaTls() throws Exception {
		final Map<String, String> headers = new LinkedHashMap<>();
		headers.put("Content-Type", "text/plain; charset=UTF-8");
		headers.put("X-Test", "value");
		headers.put("Set-Cookie", "session=abc123; Path=/; HttpOnly");
		final String url = startTlsServer(true, request -> new TestHttp2Server.Response(200, headers, "Hello HTTP/2"));

		final HttpResponse response = executeWithLocalhostTrust(new HttpRequest(HttpMethod.GET, url).setHttpVersion(HttpVersion.HTTP_2));

		assertEquals(HttpVersion.HTTP_2, response.getHttpVersion());
		assertEquals(200, response.getHttpCode());
		// HTTP/2 has no reason phrase, the standard text is used
		assertEquals("OK", response.getHttpCodeMessage());
		assertEquals("Hello HTTP/2", response.getContent());
		assertEquals("text/plain; charset=UTF-8", response.getContentType());
		// Header names are lower case in HTTP/2, but the header map is case insensitive
		assertEquals("value", response.getHeaders().get("X-Test"));
		assertEquals("abc123", response.getCookies().get("session"));
		assertTrue(response.getHeaders().keySet().stream().noneMatch(name -> name.startsWith(":")), "Pseudo headers must not be exposed: " + response.getHeaders());
		assertEquals(TestHttp2Server.PROTOCOL_H2, server.getReceivedRequests().get(0).protocol());
	}

	@Test
	public void testHttp2ViaCleartextUpgrade() throws Exception {
		final String url = startCleartextServer(true, respondWith("Hello h2c"));

		final HttpResponse response = HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, url)
				.setHttpVersion(HttpVersion.HTTP_2)
				.addUrlParameter("q", "a b"));

		assertEquals(HttpVersion.HTTP_2, response.getHttpVersion());
		assertEquals("Hello h2c", response.getContent());
		final TestHttp2Server.Request receivedRequest = server.getReceivedRequests().get(0);
		assertEquals(TestHttp2Server.PROTOCOL_H2C, receivedRequest.protocol());
		assertEquals("GET", receivedRequest.method());
		assertEquals("/?q=a+b", receivedRequest.path());
	}

	@Test
	public void testHttp11RequestIsNotUpgraded() throws Exception {
		final String url = startTlsServer(true, respondWith("Hello HTTP/1.1"));

		final HttpResponse response = executeWithLocalhostTrust(new HttpRequest(HttpMethod.GET, url));

		assertEquals(HttpVersion.HTTP_1_1, response.getHttpVersion());
		assertEquals("Hello HTTP/1.1", response.getContent());
		assertEquals(TestHttp2Server.PROTOCOL_HTTP_1_1, server.getReceivedRequests().get(0).protocol());
	}

	@Test
	public void testHttp2FallsBackToHttp11ViaTls() throws Exception {
		final String url = startTlsServer(false, respondWith("Only HTTP/1.1"));

		final HttpResponse response = executeWithLocalhostTrust(new HttpRequest(HttpMethod.GET, url).setHttpVersion(HttpVersion.HTTP_2));

		assertEquals(HttpVersion.HTTP_1_1, response.getHttpVersion());
		assertEquals(200, response.getHttpCode());
		assertEquals("Only HTTP/1.1", response.getContent());
		assertEquals(TestHttp2Server.PROTOCOL_HTTP_1_1, server.getReceivedRequests().get(0).protocol());
	}

	@Test
	public void testHttp2FallsBackToHttp11ViaCleartext() throws Exception {
		final String url = startCleartextServer(false, respondWith("Only HTTP/1.1"));

		final HttpResponse response = HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, url).setHttpVersion(HttpVersion.HTTP_2));

		assertEquals(HttpVersion.HTTP_1_1, response.getHttpVersion());
		assertEquals("Only HTTP/1.1", response.getContent());
	}

	@Test
	public void testHttp10ServerIsReported() throws Exception {
		try (ServerSocket serverSocket = new ServerSocket(0, 5, InetAddress.getLoopbackAddress())) {
			final Thread serverThread = new Thread(() -> {
				try (Socket socket = serverSocket.accept()) {
					socket.getInputStream().read(new byte[8192]);
					socket.getOutputStream().write("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nold server".getBytes(StandardCharsets.US_ASCII));
				} catch (@SuppressWarnings("unused") final IOException e) {
					// The test fails on the client side
				}
			});
			serverThread.setDaemon(true);
			serverThread.start();

			final HttpResponse response = HttpUtilities.executeHttpRequest(
					new HttpRequest(HttpMethod.GET, "http://localhost:" + serverSocket.getLocalPort() + "/"), Proxy.NO_PROXY);

			assertEquals(HttpVersion.HTTP_1_0, response.getHttpVersion());
			assertEquals("old server", response.getContent());
		}
	}

	@Test
	public void testHttp2PostParameters() throws Exception {
		final String url = startTlsServer(true, echoBody());

		final HttpResponse response = executeWithLocalhostTrust(new HttpRequest(url)
				.setHttpVersion(HttpVersion.HTTP_2)
				.addPostParameter("name", "Alice Smith")
				.addPostParameter("amount", 2));

		assertEquals(HttpVersion.HTTP_2, response.getHttpVersion());
		assertEquals("name=Alice+Smith&amount=2", response.getContent());
	}

	@Test
	public void testHttp2RequestBody() throws Exception {
		final String url = startTlsServer(true, echoBody());

		final HttpResponse response = executeWithLocalhostTrust(new HttpRequest(HttpMethod.PUT, url)
				.setHttpVersion(HttpVersion.HTTP_2)
				.setRequestBody("{\"name\": \"Älice\"}"));

		assertEquals(HttpVersion.HTTP_2, response.getHttpVersion());
		assertEquals("{\"name\": \"Älice\"}", response.getContent());
	}

	@Test
	public void testHttp2RequestBodyStream() throws Exception {
		final String url = startTlsServer(true, echoBody());
		final String body = "streamed ".repeat(1000);

		final HttpResponse response = executeWithLocalhostTrust(new HttpRequest(HttpMethod.POST, url)
				.setHttpVersion(HttpVersion.HTTP_2)
				.setRequestBodyContentStream(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8))));

		assertEquals(HttpVersion.HTTP_2, response.getHttpVersion());
		assertEquals(body, response.getContent());
	}

	@Test
	public void testHttp2MultipartUpload() throws Exception {
		final String url = startTlsServer(true, echoBody());

		final HttpResponse response = executeWithLocalhostTrust(new HttpRequest(url)
				.setHttpVersion(HttpVersion.HTTP_2)
				.addPostParameter("description", "Monthly report")
				.addUploadFileData("file", "report.txt", "file content".getBytes(StandardCharsets.UTF_8)));

		assertEquals(HttpVersion.HTTP_2, response.getHttpVersion());
		final String receivedBody = response.getContent();
		assertTrue(receivedBody.contains("name=\"description\""), receivedBody);
		assertTrue(receivedBody.contains("Monthly report"), receivedBody);
		assertTrue(receivedBody.contains("filename=\"report.txt\""), receivedBody);
		assertTrue(receivedBody.contains("file content"), receivedBody);
	}

	@Test
	public void testHttp2ErrorStatusReadsErrorBody() throws Exception {
		final String url = startTlsServer(true, request -> new TestHttp2Server.Response(404, "missing"));

		final HttpResponse response = executeWithLocalhostTrust(new HttpRequest(HttpMethod.GET, url).setHttpVersion(HttpVersion.HTTP_2));

		assertEquals(HttpVersion.HTTP_2, response.getHttpVersion());
		assertEquals(404, response.getHttpCode());
		assertEquals("Not Found", response.getHttpCodeMessage());
		assertEquals("missing", response.getContent());
	}

	@Test
	public void testHttp2RedirectKeepsRequestedVersion() throws Exception {
		final String baseUrl = startCleartextServer(true, request -> {
			if (request.path().startsWith("/start")) {
				return new TestHttp2Server.Response(302, Map.of("Location", "/target"), "");
			} else {
				return new TestHttp2Server.Response(200, "arrived");
			}
		});

		final HttpResponse response = HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, baseUrl + "start")
				.setHttpVersion(HttpVersion.HTTP_2)
				.setFollowRedirects(true));

		assertEquals(HttpVersion.HTTP_2, response.getHttpVersion());
		assertEquals("arrived", response.getContent());
		assertEquals(1, response.getRedirectCount());
		assertEquals(baseUrl + "target", response.getFinalUrl());
		final List<TestHttp2Server.Request> receivedRequests = server.getReceivedRequests();
		assertEquals(2, receivedRequests.size());
		// Also the redirected request was sent via HTTP/2
		assertEquals(TestHttp2Server.PROTOCOL_H2C, receivedRequests.get(1).protocol());
		assertEquals("/target", receivedRequests.get(1).path());
	}

	@Test
	public void testHttp2RejectsWrongHostnameUnlessDeactivated() throws Exception {
		// The certificate of this server is issued for "other.test", not for "localhost"
		server = TestHttp2Server.startTls(TestTlsSupport.getOtherKeystoreFile(), true, respondWith("other"));
		final String url = server.getBaseUrl() + "/";
		final TrustManager trustManager = new PemFileTrustManager(TestTlsSupport.getOtherPemFile());

		final Exception exception = assertThrows(Exception.class, () -> HttpUtilities.executeHttpRequest(
				new HttpRequest(HttpMethod.GET, url).setHttpVersion(HttpVersion.HTTP_2), Proxy.NO_PROXY, trustManager, false));
		assertTrue(exception.getMessage().contains("Cannot validate TLS server certificate"), exception.getMessage());
		assertTrue(server.getReceivedRequests().isEmpty());

		final HttpResponse response = HttpUtilities.executeHttpRequest(
				new HttpRequest(HttpMethod.GET, url).setHttpVersion(HttpVersion.HTTP_2), Proxy.NO_PROXY, trustManager, true);
		assertEquals(HttpVersion.HTTP_2, response.getHttpVersion());
		assertEquals("other", response.getContent());
	}

	@Test
	public void testHttp2DeactivatedHostnameVerificationStillChecksCertificateChain() throws Exception {
		final String url = startTlsServer(true, respondWith("secure"));

		// System truststore does not contain the self-signed test certificate
		final Exception exception = assertThrows(Exception.class, () -> HttpUtilities.executeHttpRequest(
				new HttpRequest(HttpMethod.GET, url).setHttpVersion(HttpVersion.HTTP_2), Proxy.NO_PROXY, (TrustManager) null, true));
		assertTrue(exception.getMessage().contains("(Certificate chain error)"), exception.getMessage());
		assertTrue(server.getReceivedRequests().isEmpty());
	}

	@Test
	public void testHttp2SkipsConnectionSpecificHeaders() throws Exception {
		final String url = startTlsServer(true, respondWith("ok"));

		// HttpClient would throw an IllegalArgumentException for these headers, HTTP/2 forbids them
		final HttpResponse response = executeWithLocalhostTrust(new HttpRequest(HttpMethod.GET, url)
				.setHttpVersion(HttpVersion.HTTP_2)
				.addHeader("Connection", "keep-alive")
				.addHeader("Keep-Alive", "timeout=5"));

		assertEquals(HttpVersion.HTTP_2, response.getHttpVersion());
		assertEquals("ok", response.getContent());
	}

	@Test
	public void testHttp2RejectsSocksProxy() throws Exception {
		final Proxy socksProxy = new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("localhost", 1080));

		final Exception exception = assertThrows(Exception.class, () -> HttpUtilities.executeHttpRequest(
				new HttpRequest(HttpMethod.GET, "https://localhost/").setHttpVersion(HttpVersion.HTTP_2), socksProxy));
		assertTrue(exception.getMessage().contains("not supported for HTTP/2"), exception.getMessage());
	}

	@Test
	public void testHttp11ResponseFromHttpUrlConnectionReportsVersion() throws Exception {
		final String url = startCleartextServer(false, respondWith("plain"));

		final HttpResponse response = HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, url), Proxy.NO_PROXY);

		assertEquals(HttpVersion.HTTP_1_1, response.getHttpVersion());
		assertNull(response.getFinalUrl());
	}
}