package de.soderer.utilities;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import org.junit.Assert;
import org.junit.Test;

import de.soderer.network.NetworkUtilities;

@SuppressWarnings("static-method")
public class NetworkUtilitiesTest {
	@Test
	public void testIpV4() {
		try {
			Assert.assertTrue(NetworkUtilities.isValidIpV4("0.0.0.0"));
			Assert.assertTrue(NetworkUtilities.isValidIpV4("255.255.255.255"));
			Assert.assertTrue(NetworkUtilities.isValidIpV4("192.168.0.5"));

			Assert.assertFalse(NetworkUtilities.isValidIpV4("0.0.0"));
			Assert.assertFalse(NetworkUtilities.isValidIpV4("256.0.0.0"));
			Assert.assertFalse(NetworkUtilities.isValidIpV4("0.256.0.0"));
			Assert.assertFalse(NetworkUtilities.isValidIpV4("0.0.256.0"));
			Assert.assertFalse(NetworkUtilities.isValidIpV4("0.0.0.256"));
		} catch (final Exception e) {
			Assert.fail(e.getMessage());
		}
	}

	@Test
	public void testIpV6() {
		try {
			Assert.assertTrue(NetworkUtilities.isValidIpV6("1080:0:0:0:8:800:200C:417A"));
			Assert.assertTrue(NetworkUtilities.isValidIpV6("1080:0:0:0:8:800:200c:417A"));
			Assert.assertTrue(NetworkUtilities.isValidIpV6("1080::8:800:200C:417A"));
			Assert.assertTrue(NetworkUtilities.isValidIpV6("1080::8:800:200C:417a"));
			Assert.assertTrue(NetworkUtilities.isValidIpV6("::FFFF:129.144.52.38"));
			Assert.assertTrue(NetworkUtilities.isValidIpV6("::ffff:129.144.52.38"));
			Assert.assertTrue(NetworkUtilities.isValidIpV6("::129.144.52.38"));
			Assert.assertTrue(NetworkUtilities.isValidIpV6("::FFFF:255"));

			Assert.assertFalse(NetworkUtilities.isValidIpV6("::FFFF:144.52.38"));
			Assert.assertFalse(NetworkUtilities.isValidIpV6("::ffff:144.52.38"));
			Assert.assertFalse(NetworkUtilities.isValidIpV6("::FFFF:52.38"));
			Assert.assertFalse(NetworkUtilities.isValidIpV6("::ffff:52.38"));
			Assert.assertFalse(NetworkUtilities.isValidIpV6("::52.38"));
		} catch (final Exception e) {
			Assert.fail(e.getMessage());
		}
	}

	@Test
	public void testHttpsWithPem() {
		try {
			// "Let's Encrypt R11"
			final String dst_CA_PemString = "-----BEGIN CERTIFICATE-----\n"
					+ "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\n"
					+ "-----END CERTIFICATE-----\n";

			try (InputStream dataStream = NetworkUtilities.openHttpsDataInputStreamWithPemCertificate("https://soderer.de", new ByteArrayInputStream(dst_CA_PemString.getBytes(StandardCharsets.UTF_8)))) {
				Assert.assertTrue(dataStream != null);
				final String data = toString(dataStream, StandardCharsets.UTF_8);
				Assert.assertTrue(data != null && data.length() > 10);
			}
		} catch (final Exception e) {
			Assert.fail(e.getMessage());
		}
	}

	@Test
	public void testHostnamePatternMatches() {
		try {
			Assert.assertTrue(NetworkUtilities.hostnamePatternMatches("subdomain.myDomain", "*.myDomain"));
			Assert.assertTrue(NetworkUtilities.hostnamePatternMatches("10.123.234.234", "10.*.*.*"));
			Assert.assertTrue(NetworkUtilities.hostnamePatternMatches("subdomain.other.myDomain", "subdomain.*.myDomain"));
			Assert.assertTrue(NetworkUtilities.hostnamePatternMatches("subdomain.mydomain", "*.MYDOMAIN"));

			Assert.assertFalse(NetworkUtilities.hostnamePatternMatches("notMyHost", "myHost"));
			Assert.assertFalse(NetworkUtilities.hostnamePatternMatches("subdomain.notMyDomain", "*.myDomain"));
			Assert.assertFalse(NetworkUtilities.hostnamePatternMatches("subdomain.other.NotMyDomain", "subdomain.*.myDomain"));
			Assert.assertFalse(NetworkUtilities.hostnamePatternMatches("subdomain.NotMyDomain", "subdomain.*.myDomain"));
		} catch (final Exception e) {
			Assert.fail(e.getMessage());
		}
	}

	public static String toString(final InputStream inputStream, final Charset encoding) throws IOException {
		return new String(toByteArray(inputStream), encoding);
	}

	public static byte[] toByteArray(final InputStream inputStream) throws IOException {
		if (inputStream == null) {
			return null;
		} else {
			try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
				copy(inputStream, byteArrayOutputStream);
				return byteArrayOutputStream.toByteArray();
			}
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
