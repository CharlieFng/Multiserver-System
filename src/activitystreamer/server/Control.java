package activitystreamer.server;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import activitystreamer.util.Settings;

public class Control extends Thread {
	private static final Logger log = LogManager.getLogger();
	private static ArrayList<Connection> connections;

	private static boolean term = false;
	private static Listener listener;
	private static ListenerForSSL listener4ssl;
	
	private String keyName = "cmkey";
	private char[] keyStorePwd = "618250".toCharArray();
	private char[] keyPwd = "618250".toCharArray();
	private KeyStore keyStore;
	private SSLSocket ss = null;

	protected static Control control = null;

	public static Control getInstance() {
		if (control == null) {
			control = new Control();
		}
		return control;
	}

	public Control() {
		// initialize the connections array
		connections = new ArrayList<Connection>();

		// start a listener
		try {
			listener = new Listener();
			listener4ssl = new ListenerForSSL();
		} catch (IOException e1) {
			log.fatal("failed to startup a listening thread: " + e1);
			System.exit(-1);
		}
	}

	public Socket getSSLSocket(String hostname, int portnum) {
		
		try {
			keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			InputStream in = null;
			keyStore.load(in = Control.class.getClassLoader()
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

			SSLSocketFactory factory = context.getSocketFactory();
			ss = (SSLSocket) factory.createSocket(hostname, portnum);
		} catch (KeyStoreException e) {
			System.out.println("Control class: KeyStoreException");
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Control class: NoSuchAlgorithmException");
			e.printStackTrace();
		} catch (CertificateException e) {
			System.out.println("Control class: CertificateException");
			e.printStackTrace();
		} catch (IOException e) {
			System.out.println("Control class: IOException");
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			System.out.println("Control class: UnrecoverableKeyException");
			e.printStackTrace();
		} catch (KeyManagementException e) {
			System.out.println("Control class: KeyManagementException");
			e.printStackTrace();
		}
		return ss;
	}

	public void initiateConnection() {

		// make a connection to another server if remote hostname is supplied
		if (Settings.getRemoteHostname() != null) {
			try {
				
				if(Settings.getSecureRemotePort() != 0){
					outgoingConnection(getSSLSocket(Settings.getRemoteHostname(),Settings.getSecureRemotePort()));
				}else{
					outgoingConnection(new Socket(Settings.getRemoteHostname(),
							Settings.getRemotePort()));
				}
				
			} catch (IOException e) {
				if(Settings.getSecureRemotePort() != 0){
					log.error("failed to make connection to "
							+ Settings.getRemoteHostname() + ":"
							+ Settings.getSecureRemotePort() + " :" + e);
				}else{
					log.error("failed to make connection to "
							+ Settings.getRemoteHostname() + ":"
							+ Settings.getRemotePort() + " :" + e);
				}
				System.exit(-1);
			}
		}
	}

	/*
	 * Processing incoming messages from the connection. Return true if the
	 * connection should close.
	 */
	public synchronized boolean process(Connection con, String msg) {
		return true;
	}

	/*
	 * The connection has been closed by the other party.
	 */
	public synchronized void connectionClosed(Connection con) {
		if (!term)
			connections.remove(con);
	}

	/*
	 * A new incoming connection has been established, and a reference is
	 * returned to it
	 */
	public synchronized Connection incomingConnection(Socket s)
			throws IOException {
		log.debug("incomming connection: " + Settings.socketAddress(s));
		Connection c = new Connection(s);
		connections.add(c);
		return c;

	}

	/*
	 * A new outgoing connection has been established, and a reference is
	 * returned to it
	 */
	public synchronized Connection outgoingConnection(Socket s)
			throws IOException {
		log.debug("outgoing connection: " + Settings.socketAddress(s));
		Connection c = new Connection(s);
		connections.add(c);
		return c;

	}

	@Override
	public void run() {
		log.info("using activity interval of " + Settings.getActivityInterval()
				+ " milliseconds");
		while (!term) {
			// do something with 5 second intervals in between
			try {
				Thread.sleep(Settings.getActivityInterval());
			} catch (InterruptedException e) {
				log.info("received an interrupt, system is shutting down");
				break;
			}
			if (!term) {
				// log.debug("doing activity");
				term = doActivity();
			}

		}
		log.info("closing " + connections.size() + " connections"); // ??
		// clean up
		for (Connection connection : connections) {
			connection.closeCon();
		}
		listener.setTerm(true);
	}

	public boolean doActivity() {
		return false;
	}

	public final void setTerm(boolean t) {
		term = t;
	}

	public final ArrayList<Connection> getConnections() {
		return connections;
	}
	
	public static Listener getListener() {
		return listener;
	}
	
	public static ListenerForSSL getListener4ssl() {
		return listener4ssl;
	}
}
