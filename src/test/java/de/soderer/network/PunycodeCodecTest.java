package de.soderer.network;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;

@SuppressWarnings("static-method")
public class PunycodeCodecTest {
	/**
	 * A simple string for testing, which includes all german characters
	 */
	public static final String GERMAN_TEST_STRING = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \u00E4\u00F6\u00FC\u00DF\u00C4\u00D6\u00DC\u00B5!?\u00A7@\u20AC$%&/\\<>(){}[]'\"\u00B4`^\u00B0\u00B9\u00B2\u00B3*#.,;:=+-~_|\u00BD\u00BC\u00AC";

	@Test
	public void testPunycode1() {
		try {
			final String punycode = PunycodeCodec.encode(GERMAN_TEST_STRING);
			final String expected = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !?@$%&/\\<>(){}[]'\"`^*#.,;:=+-~_|-3dd92chmsgwdqewdvx0krdw8ag4dssek1so8dhtz957z";
			assertEquals(expected, punycode);
			final String result = PunycodeCodec.decode(punycode);
			assertEquals(GERMAN_TEST_STRING, result);
		} catch (final Exception e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void testPunycode2() {
		try {
			final String result = PunycodeCodec.encode("abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890");
			assertEquals("abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", result);
		} catch (final Exception e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void testPunycode3() {
		try {
			final String result = PunycodeCodec.encode("österreich.at");
			assertEquals("sterreich.at-3ib", result);
		} catch (final Exception e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void testPunycode4() {
		try {
			final String punycode = PunycodeCodec.encodeDomainName("Östereich.aäd");
			assertEquals("xn--stereich-m4a.xn--ad-via", punycode);
			final String result = PunycodeCodec.decodeDomainName(punycode);
			assertEquals("östereich.aäd", result);
		} catch (final Exception e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void testPunycode5() {
		try {
			final String punycode = PunycodeCodec.encodeEmailAddress("Jemand@Östereich.at");
			assertEquals("Jemand@xn--stereich-m4a.at", punycode);
			final String result = PunycodeCodec.decodeEmailAddress(punycode);
			assertEquals("Jemand@östereich.at", result);
		} catch (final Exception e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void testPunycode6() {
		try {
			PunycodeCodec.encodeEmailAddress("Jemand@.Östereich.at");
			fail("Missing expected exception");
		} catch (@SuppressWarnings("unused") final Exception e) {
			// Expected exception
		}
	}

	@Test
	public void testPunycode7() {
		try {
			final String punycode = PunycodeCodec.encodeEmailAddress("Norm.mail@example.com");
			assertEquals("Norm.mail@example.com", punycode);
			final String result = PunycodeCodec.decodeEmailAddress(punycode);
			assertEquals("Norm.mail@example.com", result);
		} catch (final Exception e) {
			fail(e.getMessage());
		}
	}
}
