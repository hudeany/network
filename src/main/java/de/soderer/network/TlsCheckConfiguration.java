package de.soderer.network;

import java.io.File;

import javax.net.ssl.TrustManager;

import de.soderer.network.trustmanager.AdditionalTruststoreTrustManager;
import de.soderer.network.trustmanager.PemFileTrustManager;
import de.soderer.network.trustmanager.SavingToPemFileTrustManager;
import de.soderer.network.trustmanager.SavingToTruststoreTrustManager;
import de.soderer.network.trustmanager.TrustManagerUtilities;
import de.soderer.network.trustmanager.TruststoreTrustManager;

/**
 * Configuration of the TLS server certificate check: which certificates are trusted, and whether
 * the host name must match the certificate.
 */
public class TlsCheckConfiguration {
	/**
	 * Types of TLS server certificate checks.
	 */
	public enum TlsCheckConfigurationType {
		/**
		 * Check against the system's default truststore.
		 */
		SystemTrustStore(false, false),
		/**
		 * Check only against a truststore file.
		 */
		TrustStoreFile(true, true),
		/**
		 * Check against the system's default truststore and additionally a truststore file.
		 */
		AdditionalTrustStoreFile(true, true),
		/**
		 * Trust on first use: record the first certificate to a truststore file, then only accept it.
		 */
		RecordingToTrustStoreFile(true, true),
		/**
		 * Check only against a single certificate in a PEM file.
		 */
		SingleCertificate(true, false),
		/**
		 * Trust on first use: record the first certificate to a PEM file, then only accept it.
		 */
		RecordingSingleCertificate(true, false),
		/**
		 * Accept all certificates (insecure).
		 */
		NoCheck(false, false);

		/**
		 * Whether a file is needed.
		 */
		private final boolean filePathSupported;
		/**
		 * Whether a password is supported.
		 */
		private final boolean passwordSupported;

		/**
		 * Creates a type.
		 *
		 * @param filePathSupported
		 *            whether a file is needed
		 * @param passwordSupported
		 *            whether a password is supported
		 */
		TlsCheckConfigurationType(final boolean filePathSupported, final boolean passwordSupported) {
			this.filePathSupported = filePathSupported;
			this.passwordSupported = passwordSupported;
		}

		/**
		 * Whether this type uses a truststore/PEM file path at all.
		 * For all types where this is true, the file path is also mandatory (must not be null).
		 *
		 * @return true, if a file is needed
		 */
		public boolean isFilePathSupported() {
			return filePathSupported;
		}

		/**
		 * Whether this type uses a truststore password.
		 *
		 * @return true, if a password is supported
		 */
		public boolean isPasswordSupported() {
			return passwordSupported;
		}

		/**
		 * Returns the type with the given name, ignoring case.
		 *
		 * @param tlsCheckConfigurationTypeString
		 *            the name, e.g. "NoCheck"
		 * @return the type
		 * @throws Exception
		 *             if the name is unknown
		 */
		public static TlsCheckConfigurationType getTlsCheckConfigurationByName(final String tlsCheckConfigurationTypeString) throws Exception {
			for (final TlsCheckConfigurationType httpContentType : TlsCheckConfigurationType.values()) {
				if (httpContentType.name().equalsIgnoreCase(tlsCheckConfigurationTypeString)) {
					return httpContentType;
				}
			}
			throw new Exception("Unknown TlsCheckConfigurationType: '" + tlsCheckConfigurationTypeString + "'");
		}
	}

	/**
	 * Type of the check.
	 */
	private final TlsCheckConfigurationType type;
	/**
	 * Truststore or PEM file.
	 */
	private final File trustoreOrPemFile;
	/**
	 * Truststore password.
	 */
	private final char[] trustorePassword;
	/**
	 * Whether the host name must match the certificate.
	 */
	private final boolean checkCn;

	/**
	 * Creates a configuration for a type without file.
	 *
	 * @param type
	 *            the type of the check
	 * @param checkCn
	 *            true to check that the host name matches the certificate
	 * @throws IllegalArgumentException
	 *             if the type is null or needs a file
	 */
	public TlsCheckConfiguration(final TlsCheckConfigurationType type, final boolean checkCn) {
		this(type, null, checkCn);
	}

	/**
	 * Creates a configuration with a file and without password.
	 *
	 * @param type
	 *            the type of the check
	 * @param trustoreOrPemFile
	 *            the truststore or PEM file, null for types without file
	 * @param checkCn
	 *            true to check that the host name matches the certificate
	 * @throws IllegalArgumentException
	 *             if the type is null, or the file does not fit the type
	 */
	public TlsCheckConfiguration(final TlsCheckConfigurationType type, final File trustoreOrPemFile, final boolean checkCn) {
		this(type, trustoreOrPemFile, null, checkCn);
	}

	/**
	 * Creates a configuration.
	 *
	 * @param type
	 *            the type of the check
	 * @param trustoreFile
	 *            the truststore or PEM file, null for types without file
	 * @param trustorePassword
	 *            the truststore password, null for none
	 * @param checkCn
	 *            true to check that the host name matches the certificate
	 * @throws IllegalArgumentException
	 *             if the type is null, or file or password do not fit the type
	 */
	public TlsCheckConfiguration(final TlsCheckConfigurationType type, final File trustoreFile, final char[] trustorePassword, final boolean checkCn) {
		this.type = type;
		trustoreOrPemFile = trustoreFile;
		this.trustorePassword = trustorePassword;
		this.checkCn = checkCn;

		if (type == null) {
			throw new IllegalArgumentException("TlsCheckConfigurationType must not be null");
		} else if (type.isFilePathSupported() && trustoreOrPemFile == null) {
			throw new IllegalArgumentException("TlsCheckConfigurationType '" + type.name() + "' needs truststore file parameter not to be null");
		} else if (!type.isFilePathSupported() && trustoreOrPemFile != null) {
			throw new IllegalArgumentException("TlsCheckConfigurationType '" + type.name() + "' does not support truststore file parameter");
		} else if (!type.isPasswordSupported() && trustorePassword != null && trustorePassword.length > 0) {
			throw new IllegalArgumentException("TlsCheckConfigurationType '" + type.name() + "' does not support truststore password parameter");
		}
	}

	/**
	 * Creates the trust manager for this configuration.
	 *
	 * @return the trust manager
	 * @throws Exception
	 *             if the truststore or PEM file cannot be read
	 */
	public TrustManager getTrustManager() throws Exception {
		switch(type) {
			case AdditionalTrustStoreFile:
				return new AdditionalTruststoreTrustManager(trustoreOrPemFile, trustorePassword);
			case NoCheck:
				return TrustManagerUtilities.createTrustAllTrustManager();
			case RecordingSingleCertificate:
				return new SavingToPemFileTrustManager(trustoreOrPemFile);
			case RecordingToTrustStoreFile:
				return new SavingToTruststoreTrustManager(trustoreOrPemFile, trustorePassword);
			case SingleCertificate:
				return new PemFileTrustManager(trustoreOrPemFile);
			case TrustStoreFile:
				return new TruststoreTrustManager(trustoreOrPemFile, trustorePassword);
			case SystemTrustStore:
			default:
				return TrustManagerUtilities.getDefaultTrustManager();
		}
	}

	/**
	 * Returns the type of the check.
	 *
	 * @return the type
	 */
	public TlsCheckConfigurationType getType() {
		return type;
	}

	/**
	 * Returns the truststore or PEM file.
	 *
	 * @return the file, or null
	 */
	public File getTrustoreOrPemFile() {
		return trustoreOrPemFile;
	}

	/**
	 * Returns the truststore password.
	 *
	 * @return the password, or null
	 */
	public char[] getTrustorePassword() {
		return trustorePassword;
	}

	/**
	 * Returns whether the host name must match the certificate.
	 *
	 * @return true, if the host name is checked
	 */
	public boolean getCheckCn() {
		return checkCn;
	}
}