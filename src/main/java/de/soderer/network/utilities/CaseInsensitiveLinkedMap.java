package de.soderer.network.utilities;

import java.util.Locale;
import java.util.Map;

/**
 * Generic String keyed Map that ignores the String case. Keys are stored in lower case (locale
 * independent), the insertion order is kept.
 *
 * @param <V>
 *            the value type
 */
public class CaseInsensitiveLinkedMap<V> extends AbstractLinkedHashMap<String, V> {
	private static final long serialVersionUID = 6204601427841356043L;

	/**
	 * Creates an empty map.
	 *
	 * @param <V>
	 *            the value type
	 * @return the map
	 */
	public static <V> CaseInsensitiveLinkedMap<V> create() {
		return new CaseInsensitiveLinkedMap<>();
	}

	/**
	 * Creates an empty map.
	 */
	public CaseInsensitiveLinkedMap() {
		super();
	}

	/**
	 * Creates an empty map.
	 *
	 * @param initialCapacity
	 *            the initial capacity
	 * @param loadFactor
	 *            the load factor
	 * @param accessOrder
	 *            true for access order, false for insertion order
	 */
	public CaseInsensitiveLinkedMap(final int initialCapacity, final float loadFactor, final boolean accessOrder) {
		super(initialCapacity, loadFactor, accessOrder);
	}

	/**
	 * Creates an empty map.
	 *
	 * @param initialCapacity
	 *            the initial capacity
	 * @param loadFactor
	 *            the load factor
	 */
	public CaseInsensitiveLinkedMap(final int initialCapacity, final float loadFactor) {
		super(initialCapacity, loadFactor);
	}

	/**
	 * Creates an empty map.
	 *
	 * @param initialCapacity
	 *            the initial capacity
	 */
	public CaseInsensitiveLinkedMap(final int initialCapacity) {
		super(initialCapacity);
	}

	/**
	 * Creates a map with the entries of another map. Keys differing only in case are merged, the
	 * last value wins.
	 *
	 * @param map
	 *            the entries to copy
	 */
	public CaseInsensitiveLinkedMap(final Map<? extends String, ? extends V> map) {
		super(map.size());
		putAll(map);
	}

	/**
	 * Sentinel value used for lookups with a non-String key. It is never stored as an actual key (this map
	 * only ever stores lowercased Strings), so passing it to the underlying LinkedHashMap always reports
	 * "not found" instead of the previous behavior of converting any Object via toString(), which could cause
	 * false-positive matches (e.g. an Integer key 5 matching a stored String key "5").
	 */
	private static final String NON_STRING_KEY_SENTINEL = "\u0000non-string-key-sentinel-" + java.util.UUID.randomUUID();

	@Override
	protected String convertKey(final Object key) {
		if (key == null) {
			return null;
		} else if (key instanceof String) {
			return ((String) key).toLowerCase(Locale.ROOT);
		} else {
			return NON_STRING_KEY_SENTINEL;
		}
	}
}
