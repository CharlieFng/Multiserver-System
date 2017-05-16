package activitystreamer.client;

/**
 * @author siyuf 745399, jingfeiy 751315, hmen 796922, jinfengz 755121
 */
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
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
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import activitystreamer.server.Control;
import activitystreamer.util.Settings;

public class ClientSolution extends Thread {
	private static final Logger log = LogManager.getLogger();
	private static ClientSolution clientSolution;
	private TextFrame textFrame;

	private Socket socket = null;
	private DataInputStream in = null;
	private DataOutputStream out = null;
	private BufferedReader inreader = null;
	private PrintWriter outwriter = null;
	private boolean term = false;
	private JSONParser parser = new JSONParser();
	private JSONObject objSend = null;
	
	private String keyName = "cmkey";
	private char[] keyStorePwd = "618250".toCharArray();
	private char[] keyPwd = "618250".toCharArray();
	private KeyStore keyStore;
	private SSLSocket ss = null;
	/*
	 * additional variables
	 */

	// this is a singleton object
	public static ClientSolution getInstance() {
		if (clientSolution == null) {
			clientSolution = new ClientSolution();
		}
		return clientSolution;
	}

	public ClientSolution() {
		/*
		 * some additional initialization
		 */
		if (Settings.getAction() != null) {
			if (Settings.getAction().endsWith("register")) {
				connectReg();
			}
			if (Settings.getAction().equals("login")) {
				connectLogin();
			}
		} else {
			if (Settings.getUsername().equals("anonymous")
					|| Settings.getSecret() != null) {
				connectLogin();
			} else {
				connectReg();
			}
		}

		// open the gui
		log.debug("opening the gui");
		textFrame = new TextFrame();
		// start the client's thread
		start(); 
	}

	// called by the gui when the user clicks "send"
	public void sendActivityObject(JSONObject activityObj) {
		objSend = new JSONObject();
		objSend.put("command", "ACTIVITY_MESSAGE");
		objSend.put("username", Settings.getUsername());
		objSend.put("secret", Settings.getSelfSecret() != null ? Settings.getSelfSecret():Settings.getSecret());
		objSend.put("activity", activityObj);
		outwriter.println(objSend.toJSONString());
		outwriter.flush();

	}

	public void connect() {
		try {
			socket = new Socket(Settings.getRemoteHostname(),
					Settings.getRemotePort());
			out = new DataOutputStream(socket.getOutputStream());
			in = new DataInputStream(socket.getInputStream());
			outwriter = new PrintWriter(out);
			inreader = new BufferedReader(new InputStreamReader(in));
			log.info("connect successful");
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			log.info("connect failed");
			e.printStackTrace();
		}
	}
	

	
	public void connectReg() {
		try {
			if(Settings.getSecureRemotePort() != 0){
				socket = getSSLSocket(Settings.getRemoteHostname(),
						Settings.getSecureRemotePort());
			}else{
				socket = new Socket(Settings.getRemoteHostname(),
						Settings.getRemotePort());
			}
			out = new DataOutputStream(socket.getOutputStream());
			in = new DataInputStream(socket.getInputStream());
			outwriter = new PrintWriter(out);
			inreader = new BufferedReader(new InputStreamReader(in));
			objSend = new JSONObject();
			objSend.put("command", "REGISTER");
			objSend.put("username", Settings.getUsername());
			if (Settings.getSelfSecret() != null) {
				objSend.put("secret", Settings.getSelfSecret());
			} else {
				Settings.setSecret(Settings.nextSecret());
				objSend.put("secret", Settings.getSecret());
			}
			String REGISTER = objSend.toJSONString();
			outwriter.println(REGISTER);
			outwriter.flush();
			log.info("connect for registeration");
			System.out.println("user " + Settings.getUsername() + " secret is "
					+ Settings.getSelfSecret() != null ? Settings
					.getSelfSecret() : Settings.getSecret());
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			log.info("connect failed");
			e.printStackTrace();
		}
	}

	public void connectLogin() {
		try {
			if(Settings.getSecureRemotePort() != 0){
				socket = getSSLSocket(Settings.getRemoteHostname(),
						Settings.getSecureRemotePort());
			}else{
				socket = new Socket(Settings.getRemoteHostname(),
						Settings.getRemotePort());
			}
			out = new DataOutputStream(socket.getOutputStream());
			in = new DataInputStream(socket.getInputStream());
			outwriter = new PrintWriter(out);
			inreader = new BufferedReader(new InputStreamReader(in));
			objSend = new JSONObject();
			objSend.put("command", "LOGIN");
			objSend.put("username", Settings.getUsername());
			if (Settings.getSelfSecret() != null) {
				objSend.put("secret", Settings.getSelfSecret());
			} else {
				objSend.put("secret", Settings.getSecret());
			}
			String LOGIN = objSend.toJSONString();
			outwriter.println(LOGIN);
			outwriter.flush();
			log.info("connect for login");
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			log.info("connect failed");
			e.printStackTrace();
		}
	}
	
	
	
	public void reconnect(){
		try {
			socket = new Socket(Settings.getRemoteHostname(),
					Settings.getRemotePort());
			out = new DataOutputStream(socket.getOutputStream());
			in = new DataInputStream(socket.getInputStream());
			outwriter = new PrintWriter(out);
			inreader = new BufferedReader(new InputStreamReader(in));
			objSend = new JSONObject();
			objSend.put("command", "LOGIN");
			objSend.put("username", Settings.getUsername());
			if (Settings.getSelfSecret() != null) {
				objSend.put("secret", Settings.getSelfSecret());
			} else {
				objSend.put("secret", Settings.getSecret());
			}
			String LOGIN = objSend.toJSONString();
			outwriter.println(LOGIN);
			outwriter.flush();
			log.info("reconnect for login");
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			log.info("reconnect failed");
			e.printStackTrace();
		}
	}
	
	
	// called by the gui when the user clicks disconnect
	public void disconnect() {
		try {
			objSend = new JSONObject();
			objSend.put("command", "LOGOUT");
			String LOGOUT = objSend.toJSONString();
			outwriter.println(LOGOUT);
			outwriter.flush();
			inreader.close();
			outwriter.close();
			socket.close();
		} catch (IOException e) {
			// already closed?
			log.error("received exception closing the connection "
					+ Settings.socketAddress(socket) + ": " + e);
		}
		textFrame.setVisible(false);
		System.exit(0);
		/*
		 * other things to do
		 */
	}

	// the client's run method, to receive messages
	@Override
	public void run() {
		String data = null;
		JSONObject obj = null;
		try {
			while (!term) {
				data = inreader.readLine();
				if (data == null) {
					inreader.close();
					outwriter.close();
					socket.close();
					term = true;
				} else {
					obj = (JSONObject) parser.parse(data);
					textFrame.setOutputText(obj);
					if (obj.get("command").equals("REDIRECT")) {
						log.info("Sending redirect......");
						Settings.setRemoteHostname((String) obj.get("hostname"));
						long port = (Long) obj.get("port");
						Settings.setRemotePort((int) port);
						inreader.close();
						outwriter.close();
						socket.close();
						reconnect();
					} else if (obj.get("command").equals("REGISTER_SUCCESS")) {
						inreader.close();
						outwriter.close();
						socket.close();
						log.info("user " + Settings.getUsername() + " secret is "
					+ Settings.getSelfSecret() != null ? Settings
					.getSelfSecret() : Settings.getSecret());
						if(Settings.getSelfSecret() != null ){
							term = true;
						}else{
							connectLogin();
						}	
					} else if (obj.get("command").equals("REGISTER_FAILED")
							|| obj.get("command").equals("LOGIN_FAILED")) {
						term = true;
					}

				}

			}
			log.debug("connection closed to " + Settings.socketAddress(socket));

		} catch (SocketException e) {
			System.out.println("You catch me!");
			e.printStackTrace();
		} catch (IOException e) {
			System.out.println("You got me!");
			e.printStackTrace();
		} catch (ParseException e) {
			log.error("JSON parse error while parsing message: " + data);
			e.printStackTrace();
		}
	}
	
	
	
	public Socket getSSLSocket(String hostname, int portnum) {

		try {
			keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			InputStream in = null;
			keyStore.load(in = ClientSolution.class.getClassLoader()
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
	/*
	 * additional methods
	 */

}
