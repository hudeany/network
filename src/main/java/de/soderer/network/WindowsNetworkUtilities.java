package de.soderer.network;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

public class WindowsNetworkUtilities {
	private static final String WINDOWS_TCPIP_PARAMETERS_REGISTRY_KEY = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters";
	private static final long REG_QUERY_TIMEOUT_SECONDS = 5;
	private static volatile String PRIMARY_DNS_SUFFIX = null;

	public static String getPrimaryDnsSuffix() {
		if (PRIMARY_DNS_SUFFIX == null) {
			synchronized (WindowsNetworkUtilities.class) {
				if (PRIMARY_DNS_SUFFIX == null) {
					PRIMARY_DNS_SUFFIX = readPrimaryDnsSuffix();
				}
			}
		}

		return PRIMARY_DNS_SUFFIX;
	}

	public static void clearPrimaryDnsSuffixCache() {
		synchronized (WindowsNetworkUtilities.class) {
			PRIMARY_DNS_SUFFIX = null;
		}
	}

	private static String readPrimaryDnsSuffix() {
		if (!isWindowsOperatingSystem()) {
			return "";
		}

		try {
			String value = queryRegistry("Domain");
			if (isNotBlank(value)) {
				return value;
			}

			value = queryRegistry("NV Domain");
			if (isNotBlank(value)) {
				return value;
			}
		} catch (final Exception e) {
			System.err.println("Could not determine Windows Primary DNS Suffix: " + e.getMessage());
		}

		return "";
	}

	private static boolean isWindowsOperatingSystem() {
		return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("windows");
	}

	private static boolean isNotBlank(final String value) {
		return value != null && value.trim().length() > 0;
	}

	private static String queryRegistry(final String valueName) throws Exception {
		final Process process = new ProcessBuilder(
			"reg", "query",
			WINDOWS_TCPIP_PARAMETERS_REGISTRY_KEY,
			"/v", valueName
		)
			.redirectErrorStream(true)
			.start();

		final StringBuilder output = new StringBuilder();

		try (BufferedReader reader = new BufferedReader(
				new InputStreamReader(process.getInputStream(), Charset.defaultCharset()))) {

			String line;
			while ((line = reader.readLine()) != null) {
				output.append(line).append(System.lineSeparator());
			}
		}

		try {
			if (!process.waitFor(REG_QUERY_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
				throw new Exception("Timeout while querying registry value '" + valueName + "'");
			}
		} finally {
			if (process.isAlive()) {
				process.destroyForcibly();
			}
		}

		final String outputText = output.toString();
		final String registryValue = parseRegistryValue(outputText, valueName);
		if (registryValue != null) {
			return registryValue;
		} else if (process.exitValue() == 0) {
			return null;
		} else {
			throw new Exception("Registry query failed for '" + valueName + "' with exit code " + process.exitValue() + (outputText.trim().length() > 0 ? ": " + outputText.trim() : ""));
		}
	}

	private static String parseRegistryValue(final String registryOutput, final String valueName) {
		if (registryOutput == null) {
			return null;
		}

		for (final String line : registryOutput.split("\\R")) {
			final String trimmedLine = line.trim();
			if (trimmedLine.startsWith(valueName)) {
				final String[] parts = trimmedLine.split("\\s{2,}", 3);
				if (parts.length >= 3) {
					final String value = parts[2].trim();
					return value.length() > 0 ? value : null;
				}
			}
		}

		return null;
	}
}
