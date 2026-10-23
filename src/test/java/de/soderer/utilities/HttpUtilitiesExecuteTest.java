package de.soderer.utilities;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import de.soderer.network.HttpMethod;
import de.soderer.network.HttpRequest;
import de.soderer.network.HttpResponse;
import de.soderer.network.HttpUtilities;
import de.soderer.network.trustmanager.PemFileTrustManager;

/**
 * End-to-end tests of {@link HttpUtilities#executeHttpRequest} against local ephemeral-port HTTP
 * and HTTPS servers: request bodies, multipart uploads, cookies, charsets, error responses,
 * downloads, redirects, proxy authentication and TLS checks.
 */
@SuppressWarnings("static-method")
public class HttpUtilitiesExecuteTest {
	@TempDir
	File tempDir;

	/** Data of the last request received by the echo handler */
	private final Map<String, Object> received = new ConcurrentHashMap<>();

	private HttpServer server;
	private HttpServer secondServer;

	@AfterEach
	public void stopServers() {
		if (server != null) {
			server.stop(0);
		}
		if (secondServer != null) {
			secondServer.stop(0);
		}
	}

	/** Records method, URI, headers and body of the request, then answers "OK" */
	private HttpHandler recordingHandler(final int statusCode, final String responseBody) {
		return exchange -> {
			record(exchange);
			TestTlsSupport.respond(exchange, statusCode, responseBody);
		};
	}

	private void record(final HttpExchange exchange) throws IOException {
		received.put("method", exchange.getRequestMethod());
		received.put("uri", exchange.getRequestURI().toString());
		received.put("query", String.valueOf(exchange.getRequestURI().getRawQuery()));
		received.put("body", exchange.getRequestBody().readAllBytes());
		for (final Map.Entry<String, List<String>> header : exchange.getRequestHeaders().entrySet()) {
			received.put("header:" + header.getKey().toLowerCase(), String.join(", ", header.getValue()));
		}
	}

	private String receivedHeader(final String name) {
		return (String) received.get("header:" + name.toLowerCase());
	}

	private String receivedBody() {
		return new String((byte[]) received.get("body"), StandardCharsets.UTF_8);
	}

	private String baseUrl(final HttpServer httpServer) {
		return "http://localhost:" + httpServer.getAddress().getPort();
	}

	// ---------------------------------------------------------------- request building

	@Test
	public void testUrlParametersAreMergedWithExistingQueryAndFragmentIsRemoved() throws Exception {
		server = TestTlsSupport.startHttpServer(recordingHandler(200, "OK"));

		final HttpRequest request = new HttpRequest(HttpMethod.GET, baseUrl(server) + "/path?x=1#fragment");
		request.addUrlParameter("a", "b c");
		request.addUrlParameter("a", "2");
		final HttpResponse response = HttpUtilities.executeHttpRequest(request, Proxy.NO_PROXY);
		assertEquals(200, response.getHttpCode());
		assertEquals("OK", response.getContent());
		assertEquals("x=1&a=b+c&a=2", received.get("query"));
		assertNull(request.getHttpURLConnection(), "connection must be released after execution");

		HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, baseUrl(server) + "/path?only=existing"));
		assertEquals("only=existing", received.get("query"));

		HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, baseUrl(server) + "/path").addUrlParameter("n", 5));
		assertEquals("n=5", received.get("query"));

		HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, baseUrl(server) + "/path"));
		assertEquals("null", received.get("query"));
	}

	@Test
	public void testPostParametersAreSentAsHtmlForm() throws Exception {
		server = TestTlsSupport.startHttpServer(recordingHandler(200, "OK"));

		final HttpRequest request = new HttpRequest(baseUrl(server) + "/form");
		request.addPostParameter("a", "1").addPostParameter("a", "2").addPostParameter("empty", null).addPostParameter("special", "x&y=z");
		HttpUtilities.executeHttpRequest(request);
		assertEquals("POST", received.get("method"));
		assertEquals("application/x-www-form-urlencoded", receivedHeader("Content-Type"));
		assertEquals("a=1&a=2&empty=&special=x%26y%3Dz", receivedBody());

		// An explicitly set content type is kept
		final HttpRequest requestWithContentType = new HttpRequest(baseUrl(server) + "/form");
		requestWithContentType.addHeader("content-type", "application/x-www-form-urlencoded; charset=UTF-8");
		requestWithContentType.addPostParameter("b", "3");
		HttpUtilities.executeHttpRequest(requestWithContentType);
		assertEquals("application/x-www-form-urlencoded; charset=UTF-8", receivedHeader("Content-Type"));
		assertEquals("b=3", receivedBody());
	}

	@Test
	public void testTextRequestBodyUsesRequestEncoding() throws Exception {
		server = TestTlsSupport.startHttpServer(recordingHandler(200, "OK"));

		final HttpRequest request = new HttpRequest(HttpMethod.PUT, baseUrl(server) + "/text");
		request.setEncoding(StandardCharsets.ISO_8859_1);
		request.setRequestBody("äöü");
		HttpUtilities.executeHttpRequest(request);
		assertEquals("PUT", received.get("method"));
		assertEquals("text/plain; charset=ISO-8859-1", receivedHeader("Content-Type"));
		assertArrayEquals("äöü".getBytes(StandardCharsets.ISO_8859_1), (byte[]) received.get("body"));

		final HttpRequest jsonRequest = new HttpRequest(HttpMethod.POST, baseUrl(server) + "/json");
		jsonRequest.addHeader("Content-Type", "application/json");
		jsonRequest.setRequestBody("{\"a\":1}");
		HttpUtilities.executeHttpRequest(jsonRequest);
		assertEquals("application/json", receivedHeader("Content-Type"));
		assertEquals("{\"a\":1}", receivedBody());
	}

	@Test
	public void testStreamRequestBodyIsCopied() throws Exception {
		server = TestTlsSupport.startHttpServer(recordingHandler(200, "OK"));

		final byte[] data = new byte[10000];
		for (int i = 0; i < data.length; i++) {
			data[i] = (byte) i;
		}
		final HttpRequest request = new HttpRequest(HttpMethod.POST, baseUrl(server) + "/stream");
		request.setRequestBodyContentStream(new ByteArrayInputStream(data));
		HttpUtilities.executeHttpRequest(request);
		assertArrayEquals(data, (byte[]) received.get("body"));
	}

	@Test
	public void testMultipartUploadWithPostParametersAndEscapedNames() throws Exception {
		server = TestTlsSupport.startHttpServer(recordingHandler(200, "OK"));

		final HttpRequest request = new HttpRequest(HttpMethod.POST, baseUrl(server) + "/upload");
		request.addPostParameter("field", "value");
		request.addPostParameter("nullField", null);
		request.addUploadFileData("fi\"le\r\nInjected: yes", "a\\b\".txt", "file content".getBytes(StandardCharsets.UTF_8));
		request.addUploadFileData("second", null, new byte[] { 1, 2, 3 });
		HttpUtilities.executeHttpRequest(request);

		final String contentType = receivedHeader("Content-Type");
		assertTrue(contentType.startsWith("multipart/form-data; boundary="));
		final String boundary = contentType.substring(contentType.indexOf("boundary=") + 9);
		assertEquals(32, boundary.length());

		final String body = new String((byte[]) received.get("body"), StandardCharsets.ISO_8859_1);
		assertTrue(body.contains("Content-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n"));
		assertTrue(body.contains("Content-Disposition: form-data; name=\"nullField\"\r\n\r\n\r\n"));
		// CR/LF stripped, quotes and backslashes escaped
		assertTrue(body.contains("name=\"fi\\\"leInjected: yes\"; filename=\"a\\\\b\\\".txt\""));
		assertFalse(body.contains("\r\nInjected: yes"));
		assertTrue(body.contains("name=\"second\"; filename=\"\""));
		assertTrue(body.endsWith("--" + boundary + "--\r\n"));

		// The server side parser reads the data back to the original values
		final String rawRequest = "POST /upload HTTP/1.1\r\nContent-Type: " + contentType + "\r\nContent-Length: " + ((byte[]) received.get("body")).length + "\r\n\r\n";
		final ByteArrayOutputStream rawRequestBytes = new ByteArrayOutputStream();
		rawRequestBytes.write(rawRequest.getBytes(StandardCharsets.ISO_8859_1));
		rawRequestBytes.write((byte[]) received.get("body"));
		final HttpRequest parsedRequest = HttpRequest.parseHttpRequestData(new ByteArrayInputStream(rawRequestBytes.toByteArray()), 5000);
		assertEquals("value", parsedRequest.getPostParameters().get("field").get(0));
		assertEquals("fi\"leInjected: yes", parsedRequest.getUploadFileAttachments().get(0).getHtmlInputName());
		assertEquals("a\\b\".txt", parsedRequest.getUploadFileAttachments().get(0).getFileName());
		assertEquals("file content", new String(parsedRequest.getUploadFileAttachments().get(0).getData(), StandardCharsets.UTF_8));
	}

	// ---------------------------------------------------------------- response handling

	@Test
	public void testCookiesAreEncodedOnRequestAndParsedFromResponse() throws Exception {
		server = TestTlsSupport.startHttpServer(exchange -> {
			record(exchange);
			exchange.getResponseHeaders().add("Set-Cookie", "sid=abc%20def=x; Path=/; HttpOnly");
			exchange.getResponseHeaders().add("Set-Cookie", "theme=dark");
			exchange.getResponseHeaders().add("Set-Cookie", "invalidWithoutEquals; Path=/");
			exchange.getResponseHeaders().add("Set-Cookie", "=noName");
			exchange.getResponseHeaders().add("Set-Cookie", " ");
			TestTlsSupport.respond(exchange, 200, "OK");
		});

		final HttpRequest request = new HttpRequest(HttpMethod.GET, baseUrl(server) + "/cookies");
		request.addCookieData("na;me", "va=lue");
		request.addCookieData("second", "2");
		final HttpResponse response = HttpUtilities.executeHttpRequest(request);

		assertEquals("na%3Bme=va%3Dlue; second=2", receivedHeader("Cookie"));
		final Map<String, String> cookies = response.getCookies();
		assertEquals(2, cookies.size());
		assertEquals("abc def=x", cookies.get("sid"));
		assertEquals("dark", cookies.get("theme"));
		assertTrue(response.getHeaders().get("set-cookie").contains("\n"));
	}

	@Test
	public void testResponseCharsetAndMultilineContent() throws Exception {
		server = TestTlsSupport.startHttpServer(exchange -> {
			final byte[] bodyBytes = "Zeile ä\r\nZeile ö\n".getBytes(StandardCharsets.ISO_8859_1);
			exchange.getResponseHeaders().add("Content-Type", "text/plain; Charset=ISO-8859-1");
			exchange.getResponseHeaders().add("X-Multi", "a");
			exchange.getResponseHeaders().add("X-Multi", "b");
			exchange.sendResponseHeaders(200, bodyBytes.length);
			try (OutputStream outputStream = exchange.getResponseBody()) {
				outputStream.write(bodyBytes);
			}
		});

		final HttpResponse response = HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, baseUrl(server) + "/charset"));
		assertEquals("Zeile ä\nZeile ö", response.getContent());
		assertEquals("text/plain; Charset=ISO-8859-1", response.getContentType());
		// Both values are joined, but HttpURLConnection.getHeaderFields() does not guarantee their order
		// (some JDK versions deliver multi-valued headers in reverse order)
		assertEquals(java.util.Set.of("a", "b"), java.util.Set.of(response.getHeaders().get("x-multi").split(", ")));
		assertNull(response.getCookies());
		assertNotNull(response.getIpAddress());
		assertEquals(0, response.getRedirectCount());
		assertNull(response.getFinalUrl());
		assertNull(response.getDownloadedFilePath());
	}

	@Test
	public void testErrorResponsesWithAndWithoutBody() throws Exception {
		server = TestTlsSupport.startHttpServer(exchange -> {
			if (exchange.getRequestURI().getPath().equals("/missing")) {
				TestTlsSupport.respond(exchange, 404, "not here\nreally");
			} else {
				exchange.sendResponseHeaders(500, -1);
				exchange.close();
			}
		});

		final HttpResponse notFound = HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, baseUrl(server) + "/missing"));
		assertEquals(404, notFound.getHttpCode());
		assertEquals("not here\nreally", notFound.getContent());

		final HttpResponse internalError = HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, baseUrl(server) + "/error"));
		assertEquals(500, internalError.getHttpCode());
		assertNull(internalError.getContent());
		assertNull(internalError.getContentType());
	}

	@Test
	public void testIpAddressFromProxyHeaders() throws Exception {
		server = TestTlsSupport.startHttpServer(exchange -> {
			if (exchange.getRequestURI().getPath().equals("/real")) {
				exchange.getResponseHeaders().add("X-Real-IP", "10.1.2.3");
			} else {
				exchange.getResponseHeaders().add("X-Forwarded-For", " 10.4.5.6 , 10.7.8.9");
			}
			TestTlsSupport.respond(exchange, 200, "OK");
		});

		assertEquals("10.1.2.3", HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, baseUrl(server) + "/real")).getIpAddress());
		assertEquals("10.4.5.6", HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, baseUrl(server) + "/forwarded")).getIpAddress());
	}

	@Test
	public void testTimeoutsAndHeadersAreApplied() throws Exception {
		server = TestTlsSupport.startHttpServer(recordingHandler(200, "OK"));

		final HttpRequest request = new HttpRequest(HttpMethod.GET, baseUrl(server) + "/headers");
		request.setConnectionTimeoutMillis(5000).setReadTimeoutMillis(5000);
		request.addHeader("X-Custom", "custom value");
		request.addUserAgentHeader("TestAgent/1.0");
		request.addBasicAuthenticationHeader("user", "pass");
		HttpUtilities.executeHttpRequest(request);

		assertEquals("custom value", receivedHeader("X-Custom"));
		assertEquals("TestAgent/1.0", receivedHeader("User-Agent"));
		assertEquals("Basic " + Base64.getEncoder().encodeToString("user:pass".getBytes(StandardCharsets.UTF_8)), receivedHeader("Authorization"));
	}

	@Test
	public void testDebugLogOutputDoesNotChangeBehaviour() throws Exception {
		server = TestTlsSupport.startHttpServer(recordingHandler(200, "OK"));

		final Field debugLogField = HttpUtilities.class.getDeclaredField("debugLog");
		debugLogField.setAccessible(true);
		final java.io.PrintStream originalOut = System.out;
		final ByteArrayOutputStream capturedOut = new ByteArrayOutputStream();
		debugLogField.setBoolean(null, true);
		System.setOut(new java.io.PrintStream(capturedOut, true, StandardCharsets.UTF_8));
		try {
			final HttpRequest request = new HttpRequest(HttpMethod.POST, baseUrl(server) + "/debug");
			request.addHeader("X-Debug", "1");
			request.addPostParameter("p", "v");
			assertEquals(200, HttpUtilities.executeHttpRequest(request).getHttpCode());
		} finally {
			debugLogField.setBoolean(null, false);
			System.setOut(originalOut);
		}
		final String output = capturedOut.toString(StandardCharsets.UTF_8);
		assertTrue(output.contains("Requested URL: "));
		// header names are stored in lower case by the case insensitive map
		assertTrue(output.toLowerCase().contains("x-debug: 1"));
		assertTrue(output.contains("p=v"));
	}

	@Test
	public void testUnknownHostIsReported() {
		final Exception exception = assertThrows(Exception.class,
				() -> HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, "http://unknown-host-for-test.invalid/")));
		assertTrue(exception.getMessage().startsWith("Unknown host"), exception.getMessage());
	}

	@Test
	public void testUrlWithoutProtocolDefaultsToHttps() throws Exception {
		server = TestTlsSupport.startHttpServer(recordingHandler(200, "OK"));
		// "https://" is prepended, which fails against a plain HTTP server
		final HttpRequest request = new HttpRequest(HttpMethod.GET, "localhost:" + server.getAddress().getPort() + "/");
		// without read timeout the TLS handshake would wait forever for the plain HTTP server
		request.setConnectionTimeoutMillis(2000).setReadTimeoutMillis(1000);
		assertEquals("https://localhost:" + server.getAddress().getPort() + "/", request.getUrlWithProtocol());
		assertThrows(Exception.class, () -> HttpUtilities.executeHttpRequest(request, Proxy.NO_PROXY, PemFileTrustManagerHolder.get(), true));
	}

	/** Lazily created trust manager for the localhost test certificate */
	private static final class PemFileTrustManagerHolder {
		static PemFileTrustManager get() throws Exception {
			return new PemFileTrustManager(TestTlsSupport.getLocalhostPemFile());
		}
	}

	// ---------------------------------------------------------------- downloads

	@Test
	public void testDownloadToStreamAndFile() throws Exception {
		server = TestTlsSupport.startHttpServer(exchange -> TestTlsSupport.respond(exchange, 200, "download data"));

		final ByteArrayOutputStream downloadStream = new ByteArrayOutputStream();
		final HttpResponse streamResponse = HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, baseUrl(server) + "/file").setDownloadStream(downloadStream));
		assertEquals("File downloaded", streamResponse.getContent());
		assertEquals("download data", downloadStream.toString(StandardCharsets.UTF_8));

		final File downloadFile = new File(tempDir, "download.txt");
		final HttpResponse fileResponse = HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, baseUrl(server) + "/file").setDownloadFile(downloadFile));
		assertEquals("File downloaded", fileResponse.getContent());
		assertEquals(downloadFile.getAbsolutePath(), fileResponse.getDownloadedFilePath());
		assertEquals("download data", Files.readString(downloadFile.toPath()));
	}

	@Test
	public void testDownloadToNonWritableFileDeletesNothingAndFails() throws Exception {
		server = TestTlsSupport.startHttpServer(exchange -> TestTlsSupport.respond(exchange, 200, "download data"));
		// A directory cannot be opened as output file
		final File directory = new File(tempDir, "dir");
		assertTrue(directory.mkdir());
		assertThrows(Exception.class, () -> HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, baseUrl(server) + "/file").setDownloadFile(directory)));
	}

	@Test
	public void testDownloadTargetDirectoryUsesContentDispositionFileName() throws Exception {
		final Map<String, String> dispositionByPath = Map.of(
				"/extended", "attachment; filename*=UTF-8''r%C3%A9port+1.txt",
				"/plain", "attachment; filename=\"../../evil:name?.txt\"",
				"/malformed", "attachment; filename*=UTF-8''bad%zz; filename=\"fallback.txt\"",
				"/dots", "attachment; filename=\"...\"",
				"/inline", "inline; filename=\"shown.txt\"");
		server = TestTlsSupport.startHttpServer(exchange -> {
			final String disposition = dispositionByPath.get(exchange.getRequestURI().getPath());
			if (disposition != null) {
				exchange.getResponseHeaders().add("Content-Disposition", disposition);
			} else if (exchange.getRequestURI().getPath().startsWith("/attachment")) {
				exchange.getResponseHeaders().add("Content-Disposition", "attachment");
			}
			TestTlsSupport.respond(exchange, 200, "content of " + exchange.getRequestURI().getPath());
		});

		assertEquals("réport+1.txt", downloadToDirectory("/extended").getName());
		assertEquals("evil_name_.txt", downloadToDirectory("/plain").getName());
		assertEquals("fallback.txt", downloadToDirectory("/malformed").getName());
		assertEquals("download", downloadToDirectory("/dots").getName());
		assertEquals("file name+x.bin", downloadToDirectory("/attachment/file%20name+x.bin?query=1").getName());
		assertEquals("download (1)", downloadToDirectory("/attachment/").getName());

		// Name collisions get an ascending suffix, also before the extension
		assertEquals("réport+1 (1).txt", downloadToDirectory("/extended").getName());
		assertEquals("réport+1 (2).txt", downloadToDirectory("/extended").getName());

		// Without "attachment" disposition the content is returned as text instead
		final HttpResponse inlineResponse = HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, baseUrl(server) + "/inline").setDownloadTarget(tempDir));
		assertEquals("content of /inline", inlineResponse.getContent());
		assertNull(inlineResponse.getDownloadedFilePath());
		final HttpResponse noDispositionResponse = HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, baseUrl(server) + "/none").setDownloadTarget(tempDir));
		assertEquals("content of /none", noDispositionResponse.getContent());
	}

	@Test
	public void testDownloadTargetFile() throws Exception {
		server = TestTlsSupport.startHttpServer(exchange -> {
			exchange.getResponseHeaders().add("Content-Disposition", "attachment; filename=\"ignored.txt\"");
			TestTlsSupport.respond(exchange, 200, "data");
		});

		final File targetFile = new File(tempDir, "target.dat");
		final HttpResponse first = HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, baseUrl(server) + "/x").setDownloadTarget(targetFile));
		assertEquals(targetFile.getAbsolutePath(), first.getDownloadedFilePath());
		assertTrue(first.getContent().startsWith("File downloaded to '"));
		assertEquals("data", Files.readString(targetFile.toPath()));

		final HttpResponse second = HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, baseUrl(server) + "/x").setDownloadTarget(targetFile));
		assertEquals(new File(tempDir, "target (1).dat").getAbsolutePath(), second.getDownloadedFilePath());

		// File without extension
		final File noExtension = new File(tempDir, "README");
		assertTrue(noExtension.createNewFile());
		final HttpResponse third = HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, baseUrl(server) + "/x").setDownloadTarget(noExtension));
		assertEquals(new File(tempDir, "README (1)").getAbsolutePath(), third.getDownloadedFilePath());
	}

	private File downloadToDirectory(final String path) throws Exception {
		final HttpResponse response = HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, baseUrl(server) + path).setDownloadTarget(tempDir));
		assertNotNull(response.getDownloadedFilePath(), "Expected a download for " + path);
		final File downloadedFile = new File(response.getDownloadedFilePath());
		assertEquals(tempDir.getAbsolutePath(), downloadedFile.getParentFile().getAbsolutePath());
		assertTrue(downloadedFile.exists());
		return downloadedFile;
	}

	// ---------------------------------------------------------------- redirects

	@Test
	public void testRedirectNotFollowedWhenDisabled() throws Exception {
		server = TestTlsSupport.startHttpServer(exchange -> {
			exchange.getResponseHeaders().add("Location", "/target");
			TestTlsSupport.respond(exchange, 302, "moved");
		});

		final HttpRequest request = new HttpRequest(HttpMethod.GET, baseUrl(server) + "/start");
		assertFalse(request.isFollowRedirects());
		final HttpResponse response = HttpUtilities.executeHttpRequest(request);
		assertEquals(302, response.getHttpCode());
		assertEquals("moved", response.getContent());
	}

	@Test
	public void testTooManyRedirectsAndEmptyLocation() throws Exception {
		server = TestTlsSupport.startHttpServer(exchange -> {
			if (exchange.getRequestURI().getPath().equals("/loop")) {
				exchange.getResponseHeaders().add("Location", "/loop");
			}
			exchange.sendResponseHeaders(302, -1);
			exchange.close();
		});

		final Exception tooMany = assertThrows(Exception.class,
				() -> HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, baseUrl(server) + "/loop").setMaxRedirects(2)));
		assertTrue(tooMany.getMessage().startsWith("Too many redirects (>2)"), tooMany.getMessage());

		final Exception emptyLocation = assertThrows(Exception.class,
				() -> HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, baseUrl(server) + "/nolocation").setFollowRedirects(true)));
		assertEquals("Redirection url was empty", emptyLocation.getMessage());
	}

	@Test
	public void testRedirectWithStreamBodyCannotBeResent() throws Exception {
		server = TestTlsSupport.startHttpServer(exchange -> {
			exchange.getRequestBody().readAllBytes();
			exchange.getResponseHeaders().add("Location", "/target");
			exchange.sendResponseHeaders(307, -1);
			exchange.close();
		});

		final HttpRequest request = new HttpRequest(HttpMethod.POST, baseUrl(server) + "/start");
		request.setRequestBodyContentStream(new ByteArrayInputStream("data".getBytes(StandardCharsets.UTF_8)));
		request.setFollowRedirects(true);
		final Exception exception = assertThrows(Exception.class, () -> HttpUtilities.executeHttpRequest(request));
		assertTrue(exception.getMessage().contains("cannot be re-sent"), exception.getMessage());
	}

	@Test
	public void testRedirectMethodHandling() throws Exception {
		server = TestTlsSupport.startHttpServer(exchange -> {
			final String path = exchange.getRequestURI().getPath();
			if (path.startsWith("/redirect/")) {
				exchange.getRequestBody().readAllBytes();
				exchange.getResponseHeaders().add("Location", "/target");
				exchange.sendResponseHeaders(Integer.parseInt(path.substring("/redirect/".length())), -1);
				exchange.close();
			} else {
				record(exchange);
				TestTlsSupport.respond(exchange, 200, exchange.getRequestMethod());
			}
		});

		// 301 and 302 downgrade a POST to GET without body
		for (final String code : new String[] { "301", "302" }) {
			final HttpRequest postRequest = new HttpRequest(HttpMethod.POST, baseUrl(server) + "/redirect/" + code).addPostParameter("p", "1").setFollowRedirects(true);
			final HttpResponse response = HttpUtilities.executeHttpRequest(postRequest);
			assertEquals("GET", response.getContent(), "for " + code);
			assertEquals(1, response.getRedirectCount());
			assertTrue(response.getFinalUrl().endsWith("/target"));
			assertEquals(0, ((byte[]) received.get("body")).length);
		}

		// 302 keeps other methods, e.g. PUT with its body
		final HttpRequest putRequest = new HttpRequest(HttpMethod.PUT, baseUrl(server) + "/redirect/302").setRequestBody("put body").setMaxRedirects(1);
		assertEquals("PUT", HttpUtilities.executeHttpRequest(putRequest).getContent());
		assertEquals("put body", receivedBody());

		// 308 keeps the method, post parameters and uploads
		final HttpRequest multipartRequest = new HttpRequest(HttpMethod.POST, baseUrl(server) + "/redirect/308").setFollowRedirects(true);
		multipartRequest.addPostParameter("field", "value").addUploadFileData("file", "f.txt", "upload".getBytes(StandardCharsets.UTF_8));
		multipartRequest.addHeader("X-Kept", "yes");
		assertEquals("POST", HttpUtilities.executeHttpRequest(multipartRequest).getContent());
		assertTrue(receivedHeader("Content-Type").startsWith("multipart/form-data"));
		assertTrue(receivedBody().contains("upload"));
		assertTrue(receivedBody().contains("value"));
		assertEquals("yes", receivedHeader("X-Kept"));
	}

	@Test
	public void testUnlimitedRedirectsAndCrossOriginCredentialFlag() throws Exception {
		secondServer = TestTlsSupport.startHttpServer(exchange -> {
			record(exchange);
			TestTlsSupport.respond(exchange, 200, "target");
		});
		// "127.0.0.1" and "localhost" are different origins
		final String crossOriginTarget = "http://127.0.0.1:" + secondServer.getAddress().getPort() + "/final";
		server = TestTlsSupport.startHttpServer(exchange -> {
			final String path = exchange.getRequestURI().getPath();
			exchange.getResponseHeaders().add("Location", "/hop1".equals(path) ? "/hop2" : crossOriginTarget);
			exchange.sendResponseHeaders(301, -1);
			exchange.close();
		});

		final HttpRequest request = new HttpRequest(HttpMethod.GET, baseUrl(server) + "/hop1");
		request.setMaxRedirects(-1);
		request.addCookieData("session", "secret");
		final HttpResponse response = HttpUtilities.executeHttpRequest(request);

		assertEquals(200, response.getHttpCode());
		assertEquals(2, response.getRedirectCount());
		assertEquals(crossOriginTarget, response.getFinalUrl());
		assertTrue(response.isCredentialsDroppedOnRedirect());
		assertNull(receivedHeader("Cookie"));
		final String description = response.toString();
		assertTrue(description.contains("Redirects: 2 -> " + crossOriginTarget + " (credentials dropped on cross-origin redirect)"), description);
	}

	// ---------------------------------------------------------------- proxy

	@Test
	public void testProxyAuthorizationHeaderIsSentToProxy() throws Exception {
		// The local server acts as HTTP proxy: it receives the absolute target URL in the request line
		server = TestTlsSupport.startHttpServer(recordingHandler(200, "via proxy"));
		final Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", server.getAddress().getPort()));

		final HttpResponse response = HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, "http://proxied-target.invalid/resource"), proxy, "proxyUser", "proxyPass", null, false);
		assertEquals("via proxy", response.getContent());
		assertEquals("http://proxied-target.invalid/resource", received.get("uri"));
		assertEquals("Basic " + Base64.getEncoder().encodeToString("proxyUser:proxyPass".getBytes(StandardCharsets.UTF_8)), receivedHeader("Proxy-Authorization"));

		// Without credentials no Proxy-Authorization header is sent
		received.clear();
		HttpUtilities.executeHttpRequest(new HttpRequest(HttpMethod.GET, "http://proxied-target.invalid/resource"), proxy, null, null, null, false);
		assertNull(receivedHeader("Proxy-Authorization"));
	}

	// ---------------------------------------------------------------- ping

	@Test
	public void testPingUrlWithoutWaitingForAnswer() throws Exception {
		server = TestTlsSupport.startHttpServer(exchange -> {
			record(exchange);
			if (exchange.getRequestURI().getPath().equals("/slow")) {
				try {
					Thread.sleep(500);
				} catch (@SuppressWarnings("unused") final InterruptedException e) {
					Thread.currentThread().interrupt();
				}
			}
			TestTlsSupport.respond(exchange, 200, "pong");
		});

		HttpUtilities.pingUrlWithoutSslCheckNoWaitForAnswer(baseUrl(server) + "/fast", null);
		assertEquals("POST", received.get("method"));

		// The short read timeout of the ping is expected and must not be thrown
		HttpUtilities.pingUrlWithoutSslCheckNoWaitForAnswer(baseUrl(server) + "/slow", Proxy.NO_PROXY);
	}
}
