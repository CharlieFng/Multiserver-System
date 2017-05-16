package activitystreamer.server;

/**
 * @author siyuf 745399, jingfeiy 751315, hmen 796922, jinfengz 755121
 */
import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import activitystreamer.util.Settings;

public class ControlSolution extends Control {
	private static final Logger log = LogManager.getLogger();

	/*
	 * additional variables as needed
	 */
	private static JSONParser parser = new JSONParser();
	private String serverId = null; 
	private String privateSecret = null;
	private ArrayList<Connection> serverConnections = new ArrayList<Connection>(); 
	private ArrayList<Connection> clientConnections = new ArrayList<Connection>(); 
	private HashMap<String, String> users = new HashMap<String, String>();
	private HashMap<String, JSONObject> serversInfo = new HashMap<String, JSONObject>();
	private HashMap<Connection, JSONObject> serverConnectionsInfo = new HashMap<Connection, JSONObject>();
	private HashMap<Connection, ArrayList<String>> currentRegistions = new HashMap<Connection, ArrayList<String>>();

	// since control and its subclasses are singleton, we get the singleton this way
	public static ControlSolution getInstance() {
		if (control == null) {
			control = new ControlSolution();
		}
		return (ControlSolution) control;
	}

	public ControlSolution() {
		super();
		/*
		 * Do some further initialization here if necessary
		 */

		serverId = Settings.nextSecret(); 
		privateSecret = Settings.nextSecret(); 

		// check if we should initiate a connection and do so if necessary
		initiateConnection();

		// start the server's activity loop
		// it will call doActivity every few seconds
		start();
	}

	/*
	 * a new incoming connection
	 */
	@Override
	public Connection incomingConnection(Socket s) throws IOException {
		Connection con = super.incomingConnection(s);
		/*
		 * do additional things here
		 */
		return con;
	}

	/*
	 * a new outgoing connection
	 */
	@Override
	public Connection outgoingConnection(Socket s) throws IOException {
		Connection con = super.outgoingConnection(s);
		/*
		 * do additional things here
		 */

		serverConnections.add(con);

		JSONObject jsonObjSend = new JSONObject(); 
		jsonObjSend.put("command", "AUTHENTICATE");
		jsonObjSend.put("hostname", Settings.getLocalHostname());
		jsonObjSend.put("port", Settings.getLocalPort());
		jsonObjSend.put("secret", Settings.getSecret());
		String AUTHENTICATE = jsonObjSend.toJSONString();
		con.writeMsg(AUTHENTICATE);
		return con;
	}

	/*
	 * the connection has been closed
	 */
	@Override
	public void connectionClosed(Connection con) {
		super.connectionClosed(con);
		/*
		 * do additional things here
		 */
		if (serverConnections.contains(con)) {
			serverConnections.remove(con);
		}
		if (clientConnections.contains(con)) {
			clientConnections.remove(con);
		}
		log.info("broadcast the server to be deleted to other servers");
		if (serverConnectionsInfo.containsKey(con)) {
			Iterator iter = serversInfo.entrySet().iterator();
			JSONObject info = serverConnectionsInfo.get(con);
			String serverName = (String) info.get("hostname");
			long serverPort = (Long) info.get("port");
			while (iter.hasNext()) {
				Map.Entry<String, JSONObject> entry = (Map.Entry<String, JSONObject>) iter
						.next();
				JSONObject serverInfo = entry.getValue();
				String serverId = entry.getKey();
				String hostname = (String) serverInfo.get("hostname");
				long port = (Long) serverInfo.get("port");
				if (serverName.equals(hostname)
						&& (int) serverPort == (int) port) {
					serversInfo.remove(serverId);
					JSONObject jsonObjSend = new JSONObject();
					jsonObjSend.put("command", "UPDATE_SERVER_INFO");
					jsonObjSend.put("serverId", serverId);
					String UPDATE_SERVER_INFO = jsonObjSend.toJSONString();
					for (Connection serCon : serverConnections) {
						if (serCon != con) {
							serCon.writeMsg(UPDATE_SERVER_INFO);
						}
					}
					break;
				}
			}
			serverConnectionsInfo.remove(con);
		}
	}

	/*
	 * process incoming msg, from connection con return true if the connection
	 * should be closed, false otherwise
	 */
	@Override
	public synchronized boolean process(Connection con, String msg) {
		/*
		 * do additional work here return true/false as appropriate
		 */
		JSONObject jsonObjRecv = null;
		JSONObject jsonObjSend = null;

		try {
			jsonObjRecv = (JSONObject) parser.parse(msg);
		} catch (ParseException e) {
			log.error("JSON parse error while parsing message: " + msg);
			jsonObjSend = new JSONObject();
			jsonObjSend.put("command", "INVALID_MESSAGE");
			jsonObjSend.put("info", "JSON parse error while parsing message");
			String INVALID_MESSAGE = jsonObjSend.toJSONString();
			con.writeMsg(INVALID_MESSAGE);
			con.closeCon();
			e.printStackTrace();
			return true;

		}
		if (jsonObjRecv.containsKey("command")) {
			if (jsonObjRecv.get("command").equals("AUTHENTICATE")) {
				String secret = (String) jsonObjRecv.get("secret");
				if (secret.equals(this.privateSecret)) {
					if (serverConnections.contains(con)) {
						jsonObjSend = new JSONObject();
						jsonObjSend.put("command", "INVALID_MESSAGE");
						jsonObjSend
								.put("info",
										"the server had already successfully authenticated");
						String INVALID_MESSAGE = jsonObjSend.toJSONString();
						con.writeMsg(INVALID_MESSAGE);
					} else {
						log.info("authentication succeeded!");
						serverConnections.add(con);
						serverConnectionsInfo.put(con, jsonObjRecv);
						if (!users.isEmpty()) {
							log.info("synchronize user list to new server ...");
							jsonObjSend = new JSONObject();
							jsonObjSend.put("command", "SYNCHRONIZE_USERS");
							jsonObjSend.put("users", users);
							String SYNCHRONIZE_USERS = jsonObjSend
									.toJSONString();
							con.writeMsg(SYNCHRONIZE_USERS);
						}

					}

				} else {
					log.info("the supplied secret is incorrect: " + secret);
					jsonObjSend = new JSONObject();
					jsonObjSend.put("command", "AUTHENTICATION_FAIL");
					jsonObjSend.put("info", "the supplied secret is incorret: "
							+ secret);
					String AUTHENTICATION_FAIL = jsonObjSend.toJSONString();
					con.writeMsg(AUTHENTICATION_FAIL);
					con.closeCon();
					return true;
				}
			}
			if (jsonObjRecv.get("command").equals("INVALID_MESSAGE")
					|| jsonObjRecv.get("command").equals("AUTHENTICATION_FAIL")) {
				log.info(jsonObjRecv.get("info"));
				con.closeCon();
				return true;
			}

			if (jsonObjRecv.get("command").equals("REGISTER")) {
				String username = (String) jsonObjRecv.get("username");
				String secret = (String) jsonObjRecv.get("secret");

				if (users.containsKey(username)) {
					if (clientConnections.contains(con)) {
						jsonObjSend = new JSONObject();
						jsonObjSend.put("command", "INVALID_MESSAGE");
						jsonObjSend.put("info", username
								+ " has already logged in");
						String INVALID_MESSAGE = jsonObjSend.toJSONString();
						con.writeMsg(INVALID_MESSAGE);
						con.closeCon();
						return true;
					}
					log.info("check by local storage then failed");
					log.info("register failed from " + username);
					jsonObjSend = new JSONObject();
					jsonObjSend.put("command", "REGISTER_FAILED");
					jsonObjSend.put("info", username
							+ " is already registered with the system");
					String REGISTER_FAILED = jsonObjSend.toJSONString();
					con.writeMsg(REGISTER_FAILED);
					con.closeCon();
					return true;
				} else if (!users.containsKey(username)
						&& serverConnections.size() == 0) {
					users.put(username, secret);
					jsonObjSend = new JSONObject();
					jsonObjSend.put("command", "REGISTER_SUCCESS");
					jsonObjSend.put("info", "register success for " + username);
					String REGISTER_SUCCESS = jsonObjSend.toJSONString();
					con.writeMsg(REGISTER_SUCCESS);
					con.closeCon();
					log.info("register success (without request) from "
							+ username);
					return true;
				} else {
					ArrayList<String> list = new ArrayList();
					Set<String> keyset = serversInfo.keySet();
					list.add(username);
					list.add(secret);
					list.addAll(keyset);
					currentRegistions.put(con, list);
					log.info("Broadcast lock_request to all other servers");
					jsonObjSend = new JSONObject();
					jsonObjSend.put("command", "LOCK_REQUEST");
					jsonObjSend.put("username", username);
					jsonObjSend.put("secret", secret);
					String LOCK_REQUEST = jsonObjSend.toJSONString();
					for (Connection serCon : serverConnections) {
						serCon.writeMsg(LOCK_REQUEST);
					}
					System.out.println("lock_request send completed");
				}
			}

			if (jsonObjRecv.get("command").equals("LOGIN")) {

				String username = (String) jsonObjRecv.get("username");
				String secret = (String) jsonObjRecv.get("secret");

				if ((users.containsKey(username) && users.get(username).equals(
						secret))
						|| (username.equals("anonymous") && secret == null)) {

					log.info("logged in as user " + username);
					clientConnections.add(con);
					jsonObjSend = new JSONObject();
					jsonObjSend.put("command", "LOGIN_SUCCESS");
					jsonObjSend.put("info", "logged in as user " + username);
					String LOGIN_SUCCESS = jsonObjSend.toJSONString();
					con.writeMsg(LOGIN_SUCCESS);

					String targetId = null;
					Iterator iter = serversInfo.entrySet().iterator();
					while (iter.hasNext()) {
						Map.Entry<String, JSONObject> entry = (Map.Entry<String, JSONObject>) iter
								.next();
						JSONObject obj = entry.getValue();
						long temp = (Long) obj.get("load");
						if ((int) temp < (clientConnections.size() - 2)) {
							targetId = entry.getKey();
							break;
						}
					}
					if (targetId != null) {
						log.info("redirect the user " + username);
						jsonObjSend = new JSONObject();
						jsonObjSend.put("command", "REDIRECT");
						String hostname = (String) serversInfo.get(targetId)
								.get("hostname");
						long port = (Long) serversInfo.get(targetId)
								.get("port");
						jsonObjSend.put("hostname", hostname);
						jsonObjSend.put("port", (int) port);
						String REDIRECT = jsonObjSend.toJSONString();
						con.writeMsg(REDIRECT);
						con.closeCon();
						return true;
					}

				} else if (!users.containsKey(username)
						|| (users.containsKey(username) && !users.get(username)
								.equals(secret))
						|| (username.equals("anonymous") && secret != null)) {
					log.info("usrname or secret is not correct");
					jsonObjSend = new JSONObject();
					jsonObjSend.put("command", "LOGIN_FAILED");
					jsonObjSend.put("info",
							"attempt to login with wrong secret");
					String LOGIN_FAILED = jsonObjSend.toJSONString();
					con.writeMsg(LOGIN_FAILED);
					con.closeCon();
					return true;
				} else {
					log.info("loggin failed caused by invalid message");
					jsonObjSend = new JSONObject();
					jsonObjSend.put("command", "INVALID_MESSAGE");
					jsonObjSend.put("info", "loggin failed, try again");
					String INVALID_MESSAGE = jsonObjSend.toJSONString();
					con.writeMsg(INVALID_MESSAGE);
					con.closeCon();
					return true;
				}

			}
			if (jsonObjRecv.get("command").equals("LOGOUT")) {
				con.closeCon();
				return true;
			}

			if (jsonObjRecv.get("command").equals("ACTIVITY_MESSAGE")) {
				String username = (String) jsonObjRecv.get("username");
				String secret = (String) jsonObjRecv.get("secret");

				if (clientConnections.contains(con)
						&& ((users.containsKey(username) && users.get(username)
								.equals(secret)) || (username
								.equals("anonymous") && secret == null))) {
					log.info("request succeeds");
					JSONObject activity = (JSONObject) jsonObjRecv
							.get("activity");
					activity.put("authenticated_user", username);
					jsonObjSend = new JSONObject();
					jsonObjSend.put("command", "ACTIVITY_BROADCAST");
					jsonObjSend.put("activity", activity);
					String ACTIVITY_BROADCAST = jsonObjSend.toJSONString();
					for (Connection cliCon : clientConnections) {
						cliCon.writeMsg(ACTIVITY_BROADCAST);
					}
					for (Connection serCon : serverConnections) {
						serCon.writeMsg(ACTIVITY_BROADCAST);
					}
				} else if (!users.containsKey(username)
						|| (users.containsKey(username) && !users.get(username)
								.equals(secret))
						|| (username.equals("anonymous") && secret != null)
						|| !clientConnections.contains(con)) {
					log.info("Authentication failed ");
					jsonObjSend = new JSONObject();
					jsonObjSend.put("command", "AUTHENTICATION_FAIL");
					jsonObjSend
							.put("info", "username or secret is not correct");
					String AUTHENTICATION_FAIL = jsonObjSend.toJSONString();
					con.writeMsg(AUTHENTICATION_FAIL);
					con.closeCon();
					return true;
				} else {
					log.info("message is incorrect");
					jsonObjSend = new JSONObject();
					jsonObjSend.put("command", "INVALID_MESSAGE");
					jsonObjSend.put("info", "message is incorrect");
					String INVALID_MESSAGE = jsonObjSend.toJSONString();
					con.writeMsg(INVALID_MESSAGE);
					con.closeCon();
					return true;
				}
			}

			if (jsonObjRecv.get("command").equals("ACTIVITY_BROADCAST")) {
				if (serverConnections.contains(con)) {
					for (Connection cliCon : clientConnections) {
						cliCon.writeMsg(jsonObjRecv.toJSONString());
					}
					for (Connection serCon : serverConnections) {
						if (serCon != con) {
							serCon.writeMsg(jsonObjRecv.toJSONString());
						}
					}
				} else {
					log.info("Broadcast message from unauthenticated server");
					jsonObjSend = new JSONObject();
					jsonObjSend.put("command", "INVALID_MESSAGE");
					jsonObjSend.put("info", "server is not authenticated");
					String INVALID_MESSAGE = jsonObjSend.toJSONString();
					con.writeMsg(INVALID_MESSAGE);
					con.closeCon();
					return true;
				}

			}
			if (jsonObjRecv.get("command").equals("SERVER_ANNOUNCE")) {
				if (serverConnections.contains(con)) {
					String id = (String) jsonObjRecv.get("id");
					serversInfo.put(id, jsonObjRecv);

					for (Connection serCon : serverConnections) {
						if (serCon != con) {
							serCon.writeMsg(jsonObjRecv.toJSONString());
						}
					}
					// log.info("I have got a server annouce!");
				} else {
					log.info("Respond message to unauthenticated server");
					jsonObjSend = new JSONObject();
					jsonObjSend.put("command", "INVALID_MESSAGE");
					jsonObjSend.put("info", "server is not authenticated");
					String INVALID_MESSAGE = jsonObjSend.toJSONString();
					con.writeMsg(INVALID_MESSAGE);
					con.closeCon();
					return true;
				}

			}

			if (jsonObjRecv.get("command").equals("LOCK_REQUEST")) {

				String username = (String) jsonObjRecv.get("username");
				String secret = (String) jsonObjRecv.get("secret");
				log.info("receive lock request on:" + username);

				if (!serverConnections.contains(con)) {
					log.info("Respond message to unauthenticated server");
					jsonObjSend = new JSONObject();
					jsonObjSend.put("command", "INVALID_MESSAGE");
					jsonObjSend.put("info", "server is not authenticated");
					String INVALID_MESSAGE = jsonObjSend.toJSONString();
					con.writeMsg(INVALID_MESSAGE);
					con.closeCon();
					return true;
				} else {
					for (Connection serCon : serverConnections) {
						if (serCon != con) {
							serCon.writeMsg(jsonObjRecv.toJSONString());
						}
					}
					if (users.containsKey(username)
							&& !users.get(username).equals(secret)) {
						log.info("Broadcast lock_denied to all servers");
						jsonObjSend = new JSONObject();
						jsonObjSend.put("command", "LOCK_DENIED");
						jsonObjSend.put("username", username);
						jsonObjSend.put("secret", secret);
						String LOCK_DENIED = jsonObjSend.toJSONString();
						for (Connection serCon : serverConnections) {
							serCon.writeMsg(LOCK_DENIED);
						}
						log.info("lock denied has been broadcast!");
					} else if (!users.containsKey(username)) {
						log.info("Broadcast lock_allowed to all servers");
						users.put(username, secret);
						jsonObjSend = new JSONObject();
						jsonObjSend.put("command", "LOCK_ALLOWED");
						jsonObjSend.put("username", username);
						jsonObjSend.put("secret", secret);
						jsonObjSend.put("serverId", this.serverId);
						String LOCK_ALLOWED = jsonObjSend.toJSONString();
						for (Connection serCon : serverConnections) {
							serCon.writeMsg(LOCK_ALLOWED);
						}
						log.info("lock allowed has been broadcast");
					}
				}
			}

			if (jsonObjRecv.get("command").equals("LOCK_DENIED")) {

				String username = (String) jsonObjRecv.get("username");
				String secret = (String) jsonObjRecv.get("secret");
				log.info("receive lock denied on:" + username);

				if (!serverConnections.contains(con)) {
					log.info("Respond message to unauthenticated server");
					jsonObjSend = new JSONObject();
					jsonObjSend.put("command", "INVALID_MESSAGE");
					jsonObjSend.put("info", "server is not authenticated");
					String INVALID_MESSAGE = jsonObjSend.toJSONString();
					con.writeMsg(INVALID_MESSAGE);
					con.closeCon();
					return true;
				} else {

					for (Connection serCon : serverConnections) {
						if (serCon != con) {
							serCon.writeMsg(jsonObjRecv.toJSONString());
						}
					}

					if (users.containsKey(username)
							&& users.get(username).equals(secret)) {
						users.remove(username);
					}

					if (currentRegistions.size() > 0) {
						Iterator iter = currentRegistions.entrySet().iterator();
						Connection regCon = null;
						while (iter.hasNext()) {
							Map.Entry<Connection, ArrayList<String>> entry = (Map.Entry<Connection, ArrayList<String>>) iter
									.next();
							ArrayList<String> info = entry.getValue();
							if (info.get(0).equals(username)
									&& info.get(1).equals(secret)) {
								log.info("We are going to give no permission to client");
								regCon = entry.getKey();
								currentRegistions.remove(regCon);
								break;
							}
						}
						if (regCon != null) {
							log.info("register failed from " + username);
							jsonObjSend = new JSONObject();
							jsonObjSend.put("command", "REGISTER_FAILED");
							jsonObjSend.put("info", username
									+ " is already registered with the system");
							String REGISTER_FAILED = jsonObjSend.toJSONString();
							regCon.writeMsg(REGISTER_FAILED);
							regCon.closeCon();
							log.info("check by other servers, then register failed from "
									+ username);
						}
					}
				}
			}

			if (jsonObjRecv.get("command").equals("LOCK_ALLOWED")) {
				String username = (String) jsonObjRecv.get("username");
				String secret = (String) jsonObjRecv.get("secret");
				String serverId = (String) jsonObjRecv.get("serverId");
				log.info("receive lock allowed on:" + username + " from "
						+ serverId);

				if (!serverConnections.contains(con)) {
					log.info("Respond message to unauthenticated server");
					jsonObjSend = new JSONObject();
					jsonObjSend.put("command", "INVALID_MESSAGE");
					jsonObjSend.put("info", "server is not authenticated");
					String INVALID_MESSAGE = jsonObjSend.toJSONString();
					con.writeMsg(INVALID_MESSAGE);
					con.closeCon();
					return true;

				} else {
					for (Connection serCon : serverConnections) {
						if (serCon != con) {
							serCon.writeMsg(jsonObjRecv.toJSONString());
						}
					}
					if (currentRegistions.size() > 0) {
						Iterator iter = currentRegistions.entrySet().iterator();
						Connection regCon = null;
						while (iter.hasNext()) {
							Map.Entry<Connection, ArrayList<String>> entry = (Map.Entry<Connection, ArrayList<String>>) iter
									.next();
							ArrayList<String> info = entry.getValue();
							if (info.get(0).equals(username)
									&& info.get(1).equals(secret)) {
								if (info.contains(serverId)) {
									log.info("server :"
											+ serverId
											+ "help to check and return lock allowed");
									info.remove(serverId);
								}
								if (info.size() == 2) {
									regCon = entry.getKey();
									currentRegistions.remove(regCon);
								}
								break;
							}
						}
						if (regCon != null) {
							users.put(username, secret);
							jsonObjSend = new JSONObject();
							jsonObjSend.put("command", "REGISTER_SUCCESS");
							jsonObjSend.put("info", "register success for "
									+ username);
							String REGISTER_SUCCESS = jsonObjSend
									.toJSONString();
							regCon.writeMsg(REGISTER_SUCCESS);
							regCon.closeCon();
							log.info("check by other servers, then register success from "
									+ username);
						}
					}
				}
			}
			if (jsonObjRecv.get("command").equals("SYNCHRONIZE_USERS")) {
				if (serverConnections.contains(con)) {
					HashMap<String, String> usersSyn = (HashMap<String, String>) jsonObjRecv
							.get("users");
					Iterator iter = usersSyn.entrySet().iterator();
					while (iter.hasNext()) {
						Map.Entry<String, String> entry = (Map.Entry<String, String>) iter
								.next();
						String username = entry.getKey();
						if (!users.containsKey(username)) {
							users.put(username, entry.getValue());
						}
					}
					log.info("Users' info has been synchronized");
				} else {
					log.info("Broadcast message from unauthenticated server");
					jsonObjSend = new JSONObject();
					jsonObjSend.put("command", "INVALID_MESSAGE");
					jsonObjSend.put("info", "server is not authenticated");
					String INVALID_MESSAGE = jsonObjSend.toJSONString();
					con.writeMsg(INVALID_MESSAGE);
					con.closeCon();
					return true;
				}
			}
			if (jsonObjRecv.get("command").equals("UPDATE_SERVER_INFO")) {
				if (serverConnections.contains(con)) {
					String id = (String) jsonObjRecv.get("serverId");
					if (serversInfo.containsKey(id)) {
						serversInfo.remove(id);
						log.info("server " + id
								+ "has been deleted from serversInfo");
					}
					for (Connection serCon : serverConnections) {
						if (serCon != con) {
							serCon.writeMsg(jsonObjRecv.toJSONString());
						}
					}

				} else {
					log.info("Broadcast message from unauthenticated server");
					jsonObjSend = new JSONObject();
					jsonObjSend.put("command", "INVALID_MESSAGE");
					jsonObjSend.put("info", "server is not authenticated");
					String INVALID_MESSAGE = jsonObjSend.toJSONString();
					con.writeMsg(INVALID_MESSAGE);
					con.closeCon();
					return true;
				}
			}
		} else {
			log.info("the received message did contain a command: " + msg);
			jsonObjSend = new JSONObject();
			jsonObjSend.put("command", "INVALID_MESSAGE");
			jsonObjSend.put("info",
					"the received message did not contain a command");
			String INVALID_MESSAGE = jsonObjSend.toJSONString();
			con.writeMsg(INVALID_MESSAGE);
			con.closeCon();
			return true;
		}

		return false;
	}

	/*
	 * Called once every few seconds Return true if server should shut down,
	 * false otherwise
	 */
	@Override
	public boolean doActivity() {
		/*
		 * do additional work here return true/false as appropriate
		 */
		JSONObject obj = new JSONObject();
		obj.put("command", "SERVER_ANNOUNCE");
		obj.put("id", this.serverId);
		obj.put("load", clientConnections.size());
		obj.put("hostname", Settings.getLocalHostname());
		obj.put("port", Settings.getLocalPort());
		for (Connection servCon : serverConnections) {
			servCon.writeMsg(obj.toJSONString());
		}
		//System.out.println("register users: " + users);
		//System.out.println("all other servers: " + serversInfo.keySet());
		//System.out.println("server connections: " + serverConnections);
		//System.out.println("client connections: " + clientConnections);
		return false;
	}

	/*
	 * Other methods as needed
	 */

	public String getServerId() {
		return serverId;
	}

	public String getPrivateSecret() {
		return privateSecret;
	}

	public ArrayList<Connection> getServerConnections() {
		return serverConnections;
	}

	public ArrayList<Connection> getClientConnections() {
		return clientConnections;
	}

}
