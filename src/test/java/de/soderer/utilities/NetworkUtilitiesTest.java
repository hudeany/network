package de.soderer.utilities;

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
}
