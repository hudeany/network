package de.soderer.utilities;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import de.soderer.network.utilities.CaseInsensitiveLinkedMap;

/**
 * Regression tests for CaseInsensitiveLinkedMap / AbstractLinkedHashMap.
 *
 * HashMap (the superclass of LinkedHashMap) provides its own low-level implementations of
 * getOrDefault/putIfAbsent/replace/merge/compute that operate directly on the internal hash
 * table using the raw key, bypassing the overridden get(Object)/put(K,V) methods. Without
 * explicitly overriding those methods too, the map would silently behave case-sensitively for
 * exactly those methods while appearing case-insensitive everywhere else.
 */
@SuppressWarnings("static-method")
public class CaseInsensitiveLinkedMapTest {
	@Test
	public void testBasicCaseInsensitivity() {
		final CaseInsensitiveLinkedMap<String> map = new CaseInsensitiveLinkedMap<>();
		map.put("Content-Type", "text/plain");

		assertEquals("text/plain", map.get("content-type"));
		assertEquals("text/plain", map.get("CONTENT-TYPE"));
		assertTrue(map.containsKey("Content-type"));

		map.remove("CONTENT-TYPE");
		assertNull(map.get("Content-Type"));
	}

	@Test
	public void testGetOrDefault() {
		final CaseInsensitiveLinkedMap<String> map = new CaseInsensitiveLinkedMap<>();
		map.put("Key", "v1");

		assertEquals("v1", map.getOrDefault("KEY", "fallback"));
		assertEquals("fallback", map.getOrDefault("other", "fallback"));
	}

	@Test
	public void testPutIfAbsent() {
		final CaseInsensitiveLinkedMap<String> map = new CaseInsensitiveLinkedMap<>();
		map.putIfAbsent("Key", "v1");
		map.putIfAbsent("KEY", "v2");

		assertEquals("v1", map.get("key"));
		assertEquals(1, map.size());
	}

	@Test
	public void testReplace() {
		final CaseInsensitiveLinkedMap<String> map = new CaseInsensitiveLinkedMap<>();
		map.put("Key", "v1");

		map.replace("KEY", "v2");
		assertEquals("v2", map.get("key"));

		assertTrue(map.replace("key", "v2", "v3"));
		assertEquals("v3", map.get("Key"));

		assertFalse(map.replace("key", "wrong-old-value", "v4"));
		assertEquals("v3", map.get("Key"));
	}

	@Test
	public void testMerge() {
		final CaseInsensitiveLinkedMap<String> map = new CaseInsensitiveLinkedMap<>();
		map.put("Key", "v1");

		map.merge("KEY", "-v2", (oldValue, addedValue) -> oldValue + addedValue);

		assertEquals(1, map.size());
		assertEquals("v1-v2", map.get("key"));
	}

	@Test
	public void testCompute() {
		final CaseInsensitiveLinkedMap<String> map = new CaseInsensitiveLinkedMap<>();
		map.put("Key", "v1");

		map.compute("KEY", (key, oldValue) -> oldValue + "-computed");

		assertEquals(1, map.size());
		assertEquals("v1-computed", map.get("key"));
	}
}
