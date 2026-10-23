package de.soderer.utilities;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import de.soderer.network.PunycodeCodec;

/**
 * Additional tests for {@link PunycodeCodec}: null handling, code points outside the BMP,
 * upper case input and invalid Punycode.
 */
@SuppressWarnings("static-method")
public class PunycodeCodecExtendedTest {
	@Test
	public void testNullValues() throws Exception {
		assertNull(PunycodeCodec.encode(null));
		assertNull(PunycodeCodec.decode(null));
		assertNull(PunycodeCodec.encodeDomainName(null));
		assertNull(PunycodeCodec.decodeDomainName(null));
		assertNull(PunycodeCodec.encodeEmailAddress(null));
		assertNull(PunycodeCodec.decodeEmailAddress(null));
	}

	@Test
	public void testEncodeAndDecodeSamples() throws Exception {
		assertEquals("", PunycodeCodec.encode(""));
		assertEquals("abc", PunycodeCodec.encode("abc"));
		assertEquals("bcher-kva", PunycodeCodec.encode("bücher"));
		assertEquals("bücher", PunycodeCodec.decode("bcher-kva"));
		// only non-basic characters: no delimiter in the output
		assertEquals("tda", PunycodeCodec.encode("ü"));
		assertEquals("ü", PunycodeCodec.decode("tda"));
		// upper case digits are decoded like lower case ones, basic characters keep their case
		assertEquals("BüCHER", PunycodeCodec.decode("BCHER-KVA"));
	}

	@Test
	public void testSupplementaryCodePointsRoundTrip() throws Exception {
		final String emoji = new String(Character.toChars(0x1F600)) + "x";
		final String encoded = PunycodeCodec.encode(emoji);
		assertEquals("x-iv3s", encoded);
		assertEquals(emoji, PunycodeCodec.decode(encoded));

		final String mixed = "aä" + new String(Character.toChars(0x1F680)) + "中文z";
		assertEquals(mixed, PunycodeCodec.decode(PunycodeCodec.encode(mixed)));
	}

	@Test
	public void testInvalidPunycodeIsRejected() {
		// non-basic character before the delimiter
		assertThrows(Exception.class, () -> PunycodeCodec.decode("ü-abc"));
		// a character that is no Punycode digit
		assertThrows(Exception.class, () -> PunycodeCodec.decode("bcher-k!a"));
		assertThrows(Exception.class, () -> PunycodeCodec.decode("-"));
		// a number that is not terminated
		assertThrows(Exception.class, () -> PunycodeCodec.decode("bcher-z"));
		assertThrows(Exception.class, () -> PunycodeCodec.decode("zzzzzzzz"));
		// a result outside the valid code point range
		assertThrows(Exception.class, () -> PunycodeCodec.decode("999999"));
		// an integer overflow
		final Exception overflow = assertThrows(Exception.class, () -> PunycodeCodec.decode("99999999999"));
		assertTrue(overflow.getMessage().contains("overflow"));
	}

	@Test
	public void testEmailAddresses() throws Exception {
		assertEquals("user@xn--bcher-kva.de", PunycodeCodec.encodeEmailAddress("  user@bücher.de "));
		assertEquals("user@bücher.de", PunycodeCodec.decodeEmailAddress(" user@xn--bcher-kva.de  "));
		assertThrows(Exception.class, () -> PunycodeCodec.encodeEmailAddress("no-at-sign"));
		assertThrows(Exception.class, () -> PunycodeCodec.decodeEmailAddress("no-at-sign"));
	}
}
