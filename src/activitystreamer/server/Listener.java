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

public class Listener extends Thread {
	private static final Logger log = LogManager.getLogger();
	private ServerSocket serverSocket = null;
	private boolean term = false;
	private int portnum;
	private String keyName = "cmkey";
	private char[] keyStorePwd = "618250".toCharArray();
	private char[] keyPwd = "618250".toCharArray();
	private KeyStore keyStore;


	public Listener() throws IOException {
		portnum = Settings.getLocalPort(); 
		serverSocket = new ServerSocket(portnum);
		start();
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
