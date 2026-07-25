package de.soderer.network;

import java.io.File;

import javax.net.ssl.TrustManager;

import de.soderer.network.trustmanager.AdditionalTruststoreTrustManager;
import de.soderer.network.trustmanager.PemFileTrustManager;
import de.soderer.network.trustmanager.SavingToPemFileTrustManager;
import de.soderer.network.trustmanager.SavingToTruststoreTrustManager;
import de.soderer.network.trustmanager.TrustManagerUtilities;
import de.soderer.network.trustmanager.TruststoreTrustManager;

public class TlsCheckConfiguration {
	public enum TlsCheckConfigurationType {
		SystemTrustStore(false, false),
		TrustStoreFile(true, true),
		AdditionalTrustStoreFile(true, true),
		RecordingToTrustStoreFile(true, true),
		SingleCertificate(true, false),
		RecordingSingleCertificate(true, false),
		NoCheck(false, false);

		private final boolean filePathSupported;
		private final boolean passwordSupported;

		TlsCheckConfigurationType(final boolean filePathSupported, final boolean passwordSupported) {
			this.filePathSupported = filePathSupported;
			this.passwordSupported = passwordSupported;
		}

		/**
		 * Whether this type uses a truststore/PEM file path at all.
		 * For all types where this is true, the file path is also mandatory (must not be null).
		 */
		public boolean isFilePathSupported() {
			return filePathSupported;
		}

		/**
		 * Whether this type uses a truststore password.
		 */
		public boolean isPasswordSupported() {
			return passwordSupported;
		}

		public static TlsCheckConfigurationType getTlsCheckConfigurationByName(final String tlsCheckConfigurationTypeString) throws Exception {
			for (final TlsCheckConfigurationType httpContentType : TlsCheckConfigurationType.values()) {
				if (httpContentType.name().equalsIgnoreCase(tlsCheckConfigurationTypeString)) {
					return httpContentType;
				}
			}
			throw new Exception("Unknown TlsCheckConfigurationType: '" + tlsCheckConfigurationTypeString + "'");
		}
	}

	private final TlsCheckConfigurationType type;
	private final File trustoreOrPemFile;
	private final char[] trustorePassword;
	private final boolean checkCn;

	public TlsCheckConfiguration(final TlsCheckConfigurationType type, final boolean checkCn) {
		this(type, null, checkCn);
	}

	public TlsCheckConfiguration(final TlsCheckConfigurationType type, final File trustoreOrPemFile, final boolean checkCn) {
		this(type, trustoreOrPemFile, null, checkCn);
	}

	public TlsCheckConfiguration(final TlsCheckConfigurationType type, final File trustoreFile, final char[] trustorePassword, final boolean checkCn) {
		this.type = type;
		trustoreOrPemFile = trustoreFile;
		this.trustorePassword = trustorePassword;
		this.checkCn = checkCn;

		if (type.isFilePathSupported() && trustoreOrPemFile == null) {
			throw new IllegalArgumentException("TlsCheckConfigurationType '" + type.name() + "' needs truststore file parameter not to be null");
		} else if (!type.isFilePathSupported() && trustoreOrPemFile != null) {
			throw new IllegalArgumentException("TlsCheckConfigurationType '" + type.name() + "' does not support truststore file parameter");
		} else if (!type.isPasswordSupported() && trustorePassword != null && trustorePassword.length > 0) {
			throw new IllegalArgumentException("TlsCheckConfigurationType '" + type.name() + "' does not support truststore password parameter");
		}
	}

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

	public TlsCheckConfigurationType getType() {
		return type;
	}

	public File getTrustoreOrPemFile() {
		return trustoreOrPemFile;
	}

	public char[] getTrustorePassword() {
		return trustorePassword;
	}

	public boolean getCheckCn() {
		return checkCn;
	}
}