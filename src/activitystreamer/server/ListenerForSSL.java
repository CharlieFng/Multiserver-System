package activitystreamer.server;

import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import activitystreamer.util.Settings;

public class ListenerForSSL extends Thread {
	private static final Logger log = LogManager.getLogger();
	private ServerSocket serverSocket = null;
	private boolean term = false;
	private int portnum;

	public ListenerForSSL() throws IOException {
		portnum = Settings.getSecureLocalPort(); 
		serverSocket = getSSLServerSocket(portnum);
		start();
	}

	public ServerSocket getSSLServerSocket(int portnum) {
		
		String keyName = "cmkey";
		char[] keyStorePwd = "618250".toCharArray();
		char[] keyPwd = "618250".toCharArray();
		KeyStore keyStore;
		ServerSocket serverSocket = null;
		try {
			keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			InputStream in = null;
			keyStore.load(in = Listener.class.getClassLoader()
					.getResourceAsStream(keyName), keyPwd);
			in.close();

			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory
					.getDefaultAlgorithm());
			kmf.init(keyStore, keyPwd);

			SSLContext context = SSLContext.getInstance("TLS");
			context.init(kmf.getKeyManagers(),
					new TrustManager[] { new X509TrustManager() {

						@Override
						public void checkClientTrusted(X509Certificate[] chain,
								String authType) throws CertificateException {
						}

						@Override
						public void checkServerTrusted(X509Certificate[] chain,
								String authType) throws CertificateException {
						}

						@Override
						public X509Certificate[] getAcceptedIssuers() {
							return null;
						}

					} }, new SecureRandom());


			SSLServerSocketFactory factory = context.getServerSocketFactory();
			serverSocket = (SSLServerSocket) factory
					.createServerSocket(portnum);
		} catch (KeyStoreException e) {
			System.out.println("Listener class: KeyStoreException");
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Listener class: NoSuchAlgorithmException");
			e.printStackTrace();
		} catch (CertificateException e) {
			System.out.println("Listener class: CertificateException");
			e.printStackTrace();
		} catch (IOException e) {
			System.out.println("Listener class: IOException");
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			System.out.println("Listener class: UnrecoverableKeyException");
			e.printStackTrace();
		} catch (KeyManagementException e) {
			System.out.println("Listener class: KeyManagementException");
			e.printStackTrace();
		}

		return serverSocket;
	}

	@Override
	public void run() {
		log.info("listening for new connections on " + portnum);
		while (!term) {
			Socket clientSocket;
			try {
				clientSocket = serverSocket.accept();
				Control.getInstance().incomingConnection(clientSocket);
			} catch (IOException e) {
				e.printStackTrace();
				log.info("received exception, shutting down");
				term = true;
			}
		}
	}

	public ServerSocket getServerSocket() {
		return serverSocket;
	}

	public void setServerSocket(ServerSocket serverSocket) {
		this.serverSocket = serverSocket;
	}

	public void setTerm(boolean term) {
		this.term = term;
		if (term)
			interrupt();
	}

}
