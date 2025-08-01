package de.soderer.network;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketException;
import java.net.URI;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class NetworkUtilities {
	private static final String SPECIAL_CHARS_REGEXP = "\\p{Cntrl}\\(\\)<>@,;:'\\\\\\\"\\.\\[\\]";
	private static final String VALID_CHARS_REGEXP = "[^\\s" + SPECIAL_CHARS_REGEXP + "]";
	private static final String QUOTED_USER_REGEXP = "(\"[^\"]*\")";
	private static final String WORD_REGEXP = "((" + VALID_CHARS_REGEXP + "|')+|" + QUOTED_USER_REGEXP + ")";

	private static final String DOMAIN_PART_REGEX = "\\p{Alnum}(?>[\\p{Alnum}-]*\\p{Alnum})*";
	private static final String TOP_DOMAIN_PART_REGEX = "\\p{Alpha}{2,}";
	private static final String DOMAIN_NAME_REGEX = "^(?:" + DOMAIN_PART_REGEX + "\\.)+" + "(" + TOP_DOMAIN_PART_REGEX + ")$";

	private static final Pattern IPV4_PATTERN = Pattern.compile("^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])$");

	private static final Pattern IPV6_PATTERN = Pattern.compile(
			"("
					+ "([0-9A-F]{1,4}:){7,7}[0-9A-F]{1,4}|"          //# 1:2:3:4:5:6:7:8
					+ "([0-9A-F]{1,4}:){1,7}:|"                      //# 1::                              1:2:3:4:5:6:7::
					+ "([0-9A-F]{1,4}:){1,6}:[0-9A-F]{1,4}|"         //# 1::8             1:2:3:4:5:6::8  1:2:3:4:5:6::8
					+ "([0-9A-F]{1,4}:){1,5}(:[0-9A-F]{1,4}){1,2}|"  //# 1::7:8           1:2:3:4:5::7:8  1:2:3:4:5::8
					+ "([0-9A-F]{1,4}:){1,4}(:[0-9A-F]{1,4}){1,3}|"  //# 1::6:7:8         1:2:3:4::6:7:8  1:2:3:4::8
					+ "([0-9A-F]{1,4}:){1,3}(:[0-9A-F]{1,4}){1,4}|"  //# 1::5:6:7:8       1:2:3::5:6:7:8  1:2:3::8
					+ "([0-9A-F]{1,4}:){1,2}(:[0-9A-F]{1,4}){1,5}|"  //# 1::4:5:6:7:8     1:2::4:5:6:7:8  1:2::8
					+ "[0-9A-F]{1,4}:((:[0-9A-F]{1,4}){1,6})|"       //# 1::3:4:5:6:7:8   1::3:4:5:6:7:8  1::8
					+ ":((:[0-9A-F]{1,4}){1,7}|:)|"                  //# ::2:3:4:5:6:7:8  ::2:3:4:5:6:7:8 ::8       ::
					+ "FE80:(:[0-9A-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|"  //# fe80::7:8%eth0   fe80::7:8%1     (link-local IPv6 addresses with zone index)
					+ "::(FFFF(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|" //# ::255.255.255.255   ::ffff:255.255.255.255  ::ffff:0:255.255.255.255  (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
					+ "([0-9A-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])" //# 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
					+ ")", Pattern.CASE_INSENSITIVE
			);

	/**
	 * Regular expression for parsing email addresses.
	 *
	 * Taken from Apache Commons Validator.
	 * If this is not working, shame on Apache ;)
	 */
	private static final String EMAIL_REGEX = "^\\s*?(.+)@(.+?)\\s*$";

	private static final String USER_REGEX = "^\\s*" + WORD_REGEXP + "(\\." + WORD_REGEXP + ")*$";

	/** Regular expression pattern for parsing email addresses. */
	private static final Pattern EMAIL_PATTERN = Pattern.compile(EMAIL_REGEX);

	private static final Pattern USER_PATTERN = Pattern.compile(USER_REGEX);

	private static final Pattern DOMAIN_NAME_PATTERN = Pattern.compile(DOMAIN_NAME_REGEX);

	/**
	 * Connection test with 2 seconds default timeout
	 *
	 * @param hostname
	 * @param port
	 * @return
	 * @throws Exception
	 */
	public static boolean testConnection(final String hostname, final int port) throws Exception {
		return testConnection(hostname, port, 2);
	}

	public static boolean testConnection(final String hostname, final int port, final int timeoutSeconds) throws Exception {
		try (Socket socket = new Socket()) {
			final InetSocketAddress endPoint = new InetSocketAddress(hostname, port);
			if (endPoint.isUnresolved()) {
				throw new Exception("Cannot resolve hostname '" + hostname + "'");
			} else {
				try {
					if (timeoutSeconds < 1) {
						socket.connect(endPoint);
					} else {
						socket.connect(endPoint, timeoutSeconds * 1000);
					}
					return true;
				} catch (final IOException ioe) {
					throw new Exception("Cannot connect to host '" + hostname + "' on port " + port + ": " + ioe.getClass().getSimpleName() + ": " + ioe.getMessage());
				}
			}
		}
	}

	public static boolean testConnectionViaProxy(final String hostname, final int port, final int timeoutSeconds, final Proxy proxy) throws Exception {
		if (proxy == null || proxy.equals(Proxy.NO_PROXY)) {
			return testConnection(hostname, port, timeoutSeconds);
		} else {
			final String proxyHost = ((InetSocketAddress) proxy.address()).getHostName();
			final int proxyPort = ((InetSocketAddress) proxy.address()).getPort();
			try (Socket socket = new Socket(proxyHost, proxyPort)) {
				final String proxyConnect = "CONNECT " + hostname + ":" + port;

				// Add proxy credentials for later use
				//	try {
				//		String proxyUserPass = String.format("%s:%s", System.getProperty("http.proxyUser"), System.getProperty("http.proxyPass"));
				//		proxyConnect.concat(" HTTP/1.0\nProxy-Authorization:Basic " + Base64.encode(proxyUserPass.getBytes()));
				//	} catch (Exception e) {
				//	} finally {
				//		proxyConnect.concat("\n\n");
				//	}
				proxyConnect.concat("\n\n");

				socket.getOutputStream().write(proxyConnect.getBytes());

				final byte[] tmpBuffer = new byte[512];
				try (final InputStream socketInputStream = socket.getInputStream()) {
					final int proxyResponseLength = socketInputStream.read(tmpBuffer, 0, tmpBuffer.length);
					if (proxyResponseLength == 0) {
						throw new SocketException("Invalid response from proxy");
					}

					final String proxyResponse = new String(tmpBuffer, 0, proxyResponseLength, "UTF-8");
					if (proxyResponse.contains("200")) {
						if (socketInputStream.available() > 0) {
							// Flush any leftover message in buffer
							socketInputStream.skip(socketInputStream.available());
						}
						return true;
					} else {
						return false;
					}
				}
			}
		}
	}

	public static boolean ping(final String ipOrHostname, final Proxy proxy) {
		try {
			if (ipOrHostname.toLowerCase().trim().startsWith("http://")) {
				final URL url = new URL("http://" + getHostnameFromRequestString(ipOrHostname));
				HttpURLConnection httpURLConnection;
				if (proxy == null) {
					httpURLConnection = (HttpURLConnection) url.openConnection();
				} else {
					httpURLConnection = (HttpURLConnection) url.openConnection(proxy);
				}
				httpURLConnection.setConnectTimeout(20000);
				httpURLConnection.setReadTimeout(20000);
				httpURLConnection.setAllowUserInteraction(false);
				httpURLConnection.connect();
				return true;
			} else if (ipOrHostname.toLowerCase().trim().startsWith("https://")) {
				final URL url = new URL("https://" + getHostnameFromRequestString(ipOrHostname));
				HttpURLConnection httpURLConnection;
				if (proxy == null) {
					httpURLConnection = (HttpURLConnection) url.openConnection();
				} else {
					httpURLConnection = (HttpURLConnection) url.openConnection(proxy);
				}

				httpURLConnection.setConnectTimeout(20000);
				httpURLConnection.setReadTimeout(20000);
				httpURLConnection.setAllowUserInteraction(false);
				httpURLConnection.connect();
				return true;
			} else {
				return InetAddress.getByName(getHostnameFromRequestString(ipOrHostname)).isReachable(5000);
			}
		} catch (final Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	public static byte[] getMacAddressBytes(final String macAddress) throws IllegalArgumentException {
		if (isEmpty(macAddress)) {
			throw new IllegalArgumentException("Invalid MAC address");
		}

		final String[] hexParts = macAddress.split("(\\:|\\-| )");
		if (hexParts.length != 6) {
			throw new IllegalArgumentException("Invalid MAC address");
		}

		try {
			final byte[] bytes = new byte[6];
			for (int i = 0; i < 6; i++) {
				bytes[i] = (byte) Integer.parseInt(hexParts[i], 16);
			}
			return bytes;
		} catch (final NumberFormatException e) {
			throw new IllegalArgumentException("Invalid hex digit in MAC address", e);
		}
	}

	public static boolean wakeOnLanPing(final String macAddress) {
		try {
			final byte[] macBytes = getMacAddressBytes(macAddress);
			final byte[] bytes = new byte[6 + 16 * macBytes.length];
			Arrays.fill(bytes, 0, 6, (byte) 0xFF);
			for (int i = 6; i < bytes.length; i += macBytes.length) {
				System.arraycopy(macBytes, 0, bytes, i, macBytes.length);
			}

			try (DatagramSocket socket = new DatagramSocket()) {
				socket.send(new DatagramPacket(bytes, bytes.length, InetAddress.getByName("255.255.255.255"), 9));
			}

			return true;
		} catch (@SuppressWarnings("unused") final Exception e) {
			return false;
		}
	}

	public static boolean checkForNetworkConnection() {
		try {
			for (final NetworkInterface networkInterface : Collections.list(NetworkInterface.getNetworkInterfaces())) {
				if (networkInterface.isUp() && !networkInterface.isLoopback()) {
					return true;
				}
			}
			return false;
		} catch (@SuppressWarnings("unused") final SocketException e) {
			return false;
		}
	}

	public static String getHostnameFromRequestString(String requestString) {
		if (requestString == null || !requestString.contains("/")) {
			return requestString;
		} else {
			if (requestString.toLowerCase().startsWith("http")) {
				requestString = requestString.substring(requestString.indexOf("//") + 2);

				if (!requestString.contains("/")) {
					return requestString;
				}
			}

			return requestString.substring(0, requestString.indexOf("/"));
		}
	}

	public static List<X509Certificate> getTlsServerCertificates(final String host, final int port) throws Exception {
		return getTlsServerCertificates(host, port, null);
	}

	public static List<X509Certificate> getTlsServerCertificates(final String host, final int port, final Proxy proxy) throws Exception {
		try {
			final List<X509Certificate> serverCertificates = new ArrayList<>();
			final HttpsURLConnection httpsURLConnection;
			if (proxy == null) {
				httpsURLConnection = (HttpsURLConnection) new URL("https://" + host + ":" + port).openConnection();
			} else {
				httpsURLConnection = (HttpsURLConnection) new URL("https://" + host + ":" + port).openConnection(proxy);
			}
			httpsURLConnection.connect();
			final Certificate[] certificates = httpsURLConnection.getServerCertificates();
			for (final Certificate certificate : certificates) {
				if (certificate instanceof X509Certificate) {
					serverCertificates.add((X509Certificate) certificate);
				} else {
					throw new Exception("Unknown certificate type: " + certificate.getClass());
				}
			}
			return serverCertificates;
		} catch (final Exception e) {
			throw e;
		}
	}

	public static String getProtocolFromRequestString(final String requestString) {
		if (requestString.contains("://")) {
			return requestString.substring(0, requestString.indexOf("://")).toLowerCase();
		} else {
			return null;
		}
	}

	/**
	 * Get hostname of this machine
	 *
	 * @return
	 */
	public static String getHostName() {
		try {
			return InetAddress.getLocalHost().getHostName();
		} catch (@SuppressWarnings("unused") final UnknownHostException e) {
			return "Unknown hostname";
		}
	}

	public static boolean isValidDomain(final String domain) {
		String asciiDomainName;
		try {
			asciiDomainName = java.net.IDN.toASCII(domain);
		} catch (@SuppressWarnings("unused") final Exception e) {
			// invalid domain name like abc@.ch
			return false;
		}

		// Do not allow ".local" top level domain
		if (endsWithIgnoreCase(asciiDomainName, ".local")) {
			return false;
		}

		return DOMAIN_NAME_PATTERN.matcher(asciiDomainName).matches();
	}

	public static boolean isValidEmail(final String emailAddress) {
		final Matcher m = EMAIL_PATTERN.matcher(emailAddress);

		// Check, if email address matches outline structure
		if (!m.matches()) {
			return false;
		}

		// Check if user-part is valid
		if (!isValidUser(m.group(1))) {
			return false;
		}

		// Check if domain-part is valid
		if (!isValidDomain(m.group(2))) {
			return false;
		}

		return true;
	}

	public static boolean isValidUser(final String user) {
		return USER_PATTERN.matcher(user).matches();
	}

	public static boolean isValidHostname(final String value) {
		return isValidDomain(value);
	}

	public static boolean isValidHostnameOnline(final String value) {
		try {
			InetAddress.getByName(value);
			return true;
		} catch (@SuppressWarnings("unused") final UnknownHostException e) {
			return false;
		}
	}

	public static boolean isValidIpV4(final String ipv4) {
		return IPV4_PATTERN.matcher(ipv4).matches();
	}

	public static boolean isValidIpV6(final String ipv6) {
		return IPV6_PATTERN.matcher(ipv6).matches();
	}

	public static boolean isValidUri(final String uri) {
		try {
			@SuppressWarnings("unused")
			final URI unused = new URI(uri);
			return true;
		} catch (@SuppressWarnings("unused") final Exception e) {
			return false;
		}
	}

	public static InputStream openHttpsDataInputStreamWithPemCertificate(final String urlString, final InputStream pemCertificateInputStream) throws Exception {
		if (urlString == null || !urlString.toLowerCase().startsWith("https://")) {
			throw new Exception("Invalid urlString for https connection: " + urlString);
		}

		final Collection<? extends Certificate> certificates = CertificateFactory.getInstance("X.509").generateCertificates(pemCertificateInputStream);
		final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(null, null);
		int aliasId = 1;
		for (final Certificate certificate : certificates) {
			keyStore.setCertificateEntry(Integer.toString(aliasId++), certificate);
		}

		final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(keyStore);
		final SSLContext context = SSLContext.getInstance("TLS");
		context.init(null, tmf.getTrustManagers(), null);

		final URL url = new URL(urlString);

		final HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
		connection.setSSLSocketFactory(context.getSocketFactory());
		connection.connect();
		return (InputStream) connection.getContent();
	}

	public static boolean isEmpty(final String value) {
		return value == null || value.length() == 0;
	}

	public static boolean isNotEmpty(final String value) {
		return !isEmpty(value);
	}

	public static boolean isBlank(final String value) {
		return value == null || value.length() == 0 || value.trim().length() == 0;
	}

	public static boolean isNotBlank(final String value) {
		return !isBlank(value);
	}

	public static boolean endsWithIgnoreCase(final String data, final String suffix) {
		if (data == suffix) {
			// both null or same object
			return true;
		} else if (data == null) {
			// data is null but suffix is not
			return false;
		} else if (suffix == null) {
			// suffix is null but data is not
			return true;
		} else if (data.toLowerCase().endsWith(suffix.toLowerCase())) {
			// both are set, so ignore the case for standard endsWith-method
			return true;
		} else {
			// anything else
			return false;
		}
	}

	public static long copy(final InputStream inputStream, final OutputStream outputStream) throws IOException {
		final byte[] buffer = new byte[4096];
		int lengthRead;
		long bytesCopied = 0;
		while ((lengthRead = inputStream.read(buffer)) != -1) {
			outputStream.write(buffer, 0, lengthRead);
			bytesCopied += lengthRead;
		}
		outputStream.flush();
		return bytesCopied;
	}
}
