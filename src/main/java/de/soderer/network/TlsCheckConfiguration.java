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
		SystemTrustStore,
		TrustStoreFile,
		AdditionalTrustStoreFile,
		RecordingToTrustStoreFile,
		SingleCertificate,
		RecordingSingleCertificate,
		NoCheck
	}

	private final TlsCheckConfigurationType type;
	private final File trustoreOrPemFile;
	private final char[] trustorePassword;

	public TlsCheckConfiguration(final TlsCheckConfigurationType type) throws Exception {
		this(type, null);
	}

	public TlsCheckConfiguration(final TlsCheckConfigurationType type, final File trustoreOrPemFile) throws Exception {
		this(type, trustoreOrPemFile, null);
	}

	public TlsCheckConfiguration(final TlsCheckConfigurationType type, final File trustoreFile, final char[] trustorePassword) throws Exception {
		this.type = type;
		trustoreOrPemFile = trustoreFile;
		this.trustorePassword = trustorePassword;

		if (type == TlsCheckConfigurationType.TrustStoreFile && trustoreOrPemFile == null) {
			throw new Exception("TlsCheckConfigurationType 'TrustStoreFile' needs truststore file parameter not to be null");
		} else if (type == TlsCheckConfigurationType.AdditionalTrustStoreFile && trustoreOrPemFile == null) {
			throw new Exception("TlsCheckConfigurationType 'AdditionalTrustStoreFile' needs truststore file parameter not to be null");
		} else if (type == TlsCheckConfigurationType.RecordingToTrustStoreFile && trustoreOrPemFile == null) {
			throw new Exception("TlsCheckConfigurationType 'RecordingToFile' needs truststore file parameter not to be null");
		} else if (type == TlsCheckConfigurationType.NoCheck && trustoreOrPemFile != null) {
			throw new Exception("TlsCheckConfigurationType 'NoCheck' does not support truststore file parameter");
		} else if (type == TlsCheckConfigurationType.SystemTrustStore && trustoreOrPemFile != null) {
			throw new Exception("TlsCheckConfigurationType 'SystemTrustStore' does not support truststore file parameter");
		} else if (type == TlsCheckConfigurationType.SingleCertificate && trustoreOrPemFile == null) {
			throw new Exception("TlsCheckConfigurationType 'SingleCertificate' needs truststore file parameter not to be null");
		} else if (type == TlsCheckConfigurationType.RecordingSingleCertificate && trustoreOrPemFile != null) {
			throw new Exception("TlsCheckConfigurationType 'RecordingSingleCertificate' does not support truststore file parameter");
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
}
