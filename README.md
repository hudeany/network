# Network utilities for Java

[![Maven Central](https://img.shields.io/maven-central/v/de.soderer/network)](https://central.sonatype.com/artifact/de.soderer/network)

A lightweight Java library for **HTTP requests**, **TLS certificate checks** and common **network tasks**, without any external dependencies.

## Features

- **HTTP client**: all methods, URL and form parameters, JSON or other bodies, cookies, headers, basic authentication
- **File upload and download**: multipart uploads, downloads to a stream, a file or a directory (file name taken from the response)
- **Redirects**: optional, with hop limit; credentials are never forwarded to other origins
- **Timeouts** for connecting and for reading, set separately
- **Proxy support** including proxy authentication
- **Flexible TLS checks**: system truststore, own truststore (PKCS12 or JKS) or PEM certificate, trust on first use, or no check for test stages
- **HTTP request parser** for simple servers, hardened against oversized and smuggled requests
- **Network tools**: connection test (also through a proxy), ping, Wake-on-LAN, validation of IP addresses, host names and email addresses

## Contents

- [Installation](#installation)
- [HTTP requests](#http-requests)
  - [GET with parameters](#get-with-parameters)
  - [POST form data](#post-form-data)
  - [JSON or other request bodies](#json-or-other-request-bodies)
  - [File upload](#file-upload)
  - [File download](#file-download)
  - [Proxy](#proxy)
- [TLS certificate checks](#tls-certificate-checks)
- [Parse HTTP requests on server side](#parse-http-requests-on-server-side)
- [Network tools](#network-tools)

## Installation

The library is available on Maven Central. Replace `VERSION` with the version shown in the badge above.

**Maven**

```xml
<dependency>
	<groupId>de.soderer</groupId>
	<artifactId>network</artifactId>
	<version>VERSION</version>
</dependency>
```

**Gradle**

```groovy
implementation "de.soderer:network:VERSION"
```

**Without a build tool**, download the jar from the [GitHub releases](https://github.com/hudeany/network/releases).

## HTTP requests

All classes are in the package `de.soderer.network`. Requests are built with chained setters and executed by `HttpUtilities.executeHttpRequest`. The response is returned for every HTTP status code, so check `getHttpCode()`.

### GET with parameters

```java
final HttpRequest request = new HttpRequest(HttpMethod.GET, "https://example.com/api/users")
	.addUrlParameter("page", 2)
	.addHeader("Accept", "application/json")
	.setConnectionTimeoutMillis(5000)
	.setReadTimeoutMillis(30000)
	.setFollowRedirects(true);

final HttpResponse response = HttpUtilities.executeHttpRequest(request);

if (response.getHttpCode() == 200) {
	System.out.println(response.getContent());
} else {
	System.out.println("Error: " + response.getHttpCode() + " " + response.getHttpCodeMessage());
}
```

A URL without protocol gets `https://`. Use `setMaxRedirects(int)` for a custom hop limit.

### POST form data

`new HttpRequest(url)` creates a POST request. Post parameters are sent URL encoded.

```java
final HttpRequest request = new HttpRequest("https://example.com/login")
	.addPostParameter("user", "alice")
	.addPostParameter("password", "secret");
```

### JSON or other request bodies

```java
final HttpRequest request = new HttpRequest(HttpMethod.PUT, "https://example.com/api/users/42")
	.addHeader(HttpConstants.HTTPHEADERNAME_CONTENTTYPE, HttpContentType.Json.getStringRepresentation())
	.addBasicAuthenticationHeader("alice", "secret")
	.setRequestBody("{\"name\": \"Alice\"}");
```

Large bodies can be streamed with `setRequestBodyContentStream(inputStream)`.

### File upload

Files are sent as `multipart/form-data`, together with any post parameters.

```java
final HttpRequest request = new HttpRequest("https://example.com/upload")
	.addPostParameter("description", "Monthly report")
	.addUploadFileData("file", "report.pdf", Files.readAllBytes(Path.of("report.pdf")));
```

### File download

There are three ways to receive the response body instead of `getContent()`:

| Method | Behavior |
|---|---|
| `setDownloadStream(outputStream)` | Writes every response body into the stream |
| `setDownloadFile(file)` | Writes every response body into the file |
| `setDownloadTarget(directoryOrFile)` | Saves only real file downloads (`Content-Disposition: attachment`), other responses stay in `getContent()` |

With a download target directory, the file name is taken from the response. Existing files are never overwritten; like a browser, the library uses `report (1).pdf` instead.

```java
final HttpRequest request = new HttpRequest(HttpMethod.GET, "https://example.com/report.pdf")
	.setDownloadTarget(new File("downloads"));

final HttpResponse response = HttpUtilities.executeHttpRequest(request);
System.out.println(response.getDownloadedFilePath());
```

### Proxy

```java
// Explicit proxy
final Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("proxy.example.com", 3128));
// ... or from a text like "proxy.example.com:3128", "http://[::1]:3128/" or "DIRECT"
final Proxy proxyFromConfig = HttpUtilities.getProxyFromString("proxy.example.com:3128");

HttpUtilities.executeHttpRequest(request, proxy);

// Proxy with authentication
HttpUtilities.executeHttpRequest(request, proxy, "proxyUser", "proxyPassword", null, false);
```

Without a proxy parameter, the JVM's default proxy settings are used. Pass `Proxy.NO_PROXY` for a direct connection.

## TLS certificate checks

By default, server certificates are checked against the system's truststore. Another check is defined by a `TrustManager`, conveniently created by a `TlsCheckConfiguration` (the type enum is nested: `import de.soderer.network.TlsCheckConfiguration.TlsCheckConfigurationType;`):

```java
final TrustManager trustManager = new TlsCheckConfiguration(
		TlsCheckConfigurationType.TrustStoreFile, new File("truststore.p12"), "changeit".toCharArray(), true)
	.getTrustManager();

HttpUtilities.executeHttpRequest(request, Proxy.NO_PROXY, trustManager, false);
```

| Type | Trusted certificates |
|---|---|
| `SystemTrustStore` | The system's default truststore |
| `TrustStoreFile` | Only those of a truststore file (PKCS12 or JKS) |
| `AdditionalTrustStoreFile` | The system's truststore plus a truststore file, e.g. for a company CA |
| `SingleCertificate` | Only a single certificate from a PEM file |
| `RecordingToTrustStoreFile` | Trust on first use: the first certificate is saved to a truststore file, later only this one is accepted |
| `RecordingSingleCertificate` | Trust on first use, saving to a PEM file |
| `NoCheck` | All certificates. **Insecure**, only for test stages |

The trust managers are also available directly in the package `de.soderer.network.trustmanager`, e.g. `TrustManagerUtilities.createTrustManagerForKeyStore(file, password)`.

To trust a self-signed server certificate later, its certificate can be saved to a new truststore file:

```java
TrustManagerUtilities.createTrustStoreFile("myserver.local:8443", 443, new File("myserver.p12"), "changeit".toCharArray(), Proxy.NO_PROXY);
```

## Parse HTTP requests on server side

`HttpRequest.parseHttpRequestData` reads a raw HTTP/1.x request from a socket stream: request line, headers, cookies, URL and form parameters, multipart uploads and body (also chunked). Header block and body sizes are limited, and ambiguous requests that could be used for request smuggling are rejected.

```java
final String raw = "POST /orders?express=true HTTP/1.1\r\n"
		+ "Host: example.com\r\n"
		+ "Content-Type: application/x-www-form-urlencoded\r\n"
		+ "Content-Length: 18\r\n"
		+ "\r\n"
		+ "item=book&amount=2";

final HttpRequest request = HttpRequest.parseHttpRequestData(
		new ByteArrayInputStream(raw.getBytes(StandardCharsets.ISO_8859_1)), 5000);

System.out.println(request.getRequestMethod() + " " + request.getUrl()); // POST /orders?express=true
System.out.println(request.getUrlParameters());                         // {express=[true]}
System.out.println(request.getPostParameters());                        // {item=[book], amount=[2]}
```

For a socket, pass `socket.getInputStream()` and also set `socket.setSoTimeout(...)`, so a single stalled read cannot block forever.

## Network tools

```java
// Can a TCP connection be built up? (optionally through a proxy, using CONNECT)
NetworkUtilities.testConnection("example.com", 443);
NetworkUtilities.testConnection("example.com", 443, 2000, proxy);

// Wake on LAN
NetworkUtilities.wakeOnLanPing("00:80:41:AE:FD:7E");

// Validation
NetworkUtilities.isValidIpV4("192.168.0.1");                      // true
NetworkUtilities.isValidIpV6("2001:db8::1");                      // true
NetworkUtilities.isValidEmail("alice@example.com");               // true
NetworkUtilities.isValidDomain("example.com");                    // true
NetworkUtilities.hostnamePatternMatches("api.example.com", "*.example.com"); // true

// TLS certificate chain of a server
final List<X509Certificate> certificates = NetworkUtilities.getTlsServerCertificates("example.com", 443);
```
