package ch.zhaw.securitylab;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * This class serves to test SSL/TLS servers.
 * 
 * @author Marc Rennhard
 */
public class TLSTester {

	/* Variables specified via the command line parameters */
	private static String host;
	private static int port;
	private static String trustStore = null;
	private static String password = null;

	/**
	 * The run method that executes all tests - Check if the server can be
	 * reached - Print the highest TLS version supported by the server - Print
	 * the certificate chain including details about the certificates - Check
	 * which cipher suite the server supports and list the secure and insecure
	 * ones
	 * 
	 * @throws Exception
	 *             An exception occurred
	 */
	private void run() throws Exception {

		// To be implemented
		TrustManagerFactory tmf = initTrustManager();
		SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
		sslContext.init(null, tmf.getTrustManagers(), null);
		SSLSocketFactory factory = sslContext.getSocketFactory();

		printCertificatesInTruststore(tmf);

		SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
		printHighestTLSVersion(socket);
		String[] supportedSuites = socket.getSupportedCipherSuites();

		SSLSession session = socket.getSession();
		printCertificateChain(session);
		printSupportedCipherSuites(supportedSuites);
		List<String> supportedSuitesByServer = getEnabledSuitesByServer(
				factory, supportedSuites);
		printSupportedSuitesByServer(supportedSuitesByServer);

	}

	private void printCertificateChain(SSLSession session)
			throws SSLPeerUnverifiedException {
		X509Certificate[] certificates = (X509Certificate[]) session
				.getPeerCertificates();
	
		
		
		System.out.format("%d certificates found in chain\n",
				certificates.length);
		
		for (int i = 0; i < certificates.length; i++) {
			X509Certificate certificate = certificates[certificates.length-i-1];
			System.out.format("Certificate %d:\n", i+1);
			System.out.format("Subject: %s\n", certificate.getSubjectDN());
			System.out.format("Issuer: %s\n", certificate.getIssuerDN());
			System.out.format("Validity: %s - %s\n",
					certificate.getNotBefore(), certificate.getNotAfter());
			System.out.format("Algorithm: %s\n", certificate.getSigAlgName());
			System.out.format("Public Key length (modulus): %s\n", certificate
					.getPublicKey().getEncoded().length);
			System.out.println();
		}
		System.out.println();
	}

	private TrustManagerFactory initTrustManager()
			throws NoSuchAlgorithmException, KeyStoreException,
			CertificateException, FileNotFoundException, IOException {
		TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
		if (trustStore == null) {
			trustStore = "default";
			tmf.init((KeyStore) null);
			return tmf;
		} else {
			KeyStore ts = KeyStore.getInstance("JKS");
			ts.load(new FileInputStream(trustStore), password.toCharArray());
			tmf.init(ts);
			return tmf;
		}

	}

	private void printCertificatesInTruststore(TrustManagerFactory tmf) {
		final X509TrustManager tm = (X509TrustManager) tmf.getTrustManagers()[0];
		final X509Certificate[] trustedCerts = tm.getAcceptedIssuers();
		System.out.format("Use %s truststore with %d certificates\n",
				trustStore, trustedCerts.length);
	}

	private void printSupportedSuitesByServer(
			List<String> supportedSuitesByServer) {
		System.out.format(
				"The following suites %d are supported by the server:\n",
				supportedSuitesByServer.size());
		for (String suite : supportedSuitesByServer) {
			System.out.println(suite);
		}
	}

	private List<String> getEnabledSuitesByServer(SSLSocketFactory factory,
			String[] supportedSuites) {
		List<String> supportedSuitesByServer = new ArrayList<String>();
		for (String suite : supportedSuites) {
			// System.out.format("Testing %s\n", suite);
			try {
				SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
				socket.setEnabledCipherSuites(new String[] { suite });
				socket.startHandshake();
				supportedSuitesByServer.add(suite);

			} catch (Exception e) {
				// System.out.println("An error occured: "+e.getMessage());
			}

		}
		return supportedSuitesByServer;

	}

	private void printHighestTLSVersion(SSLSocket socket) {

		SSLSession session = socket.getSession();
		System.out.println(session.getProtocol());
	}

	private void printSupportedCipherSuites(String[] suites) {

		System.out.format("The following %d suites are supported:",
				suites.length);

		for (String suite : suites) {
			System.out.println(suite);
		}
	}

	/**
	 * The main method.
	 * 
	 * @param argv
	 *            The command line parameters
	 * @throws Exception
	 *             If an exception occurred
	 */
	public static void main(String argv[]) throws Exception {

		/* Create a TLSTester object, and execute the test */
		try {
			host = argv[0];
			port = Integer.parseInt(argv[1]);
			if ((port < 1) || (port > 65535)) {
				throw (new Exception());
			}
			if (argv.length > 2) {
				trustStore = argv[2];
				password = argv[3];
			}
		} catch (Exception e) {
			System.out
					.println("\nUsage: java TLSTester host port {truststore password}\n");
			System.exit(0);
		}
		TLSTester tlst = new TLSTester();
		tlst.run();
	}
}
