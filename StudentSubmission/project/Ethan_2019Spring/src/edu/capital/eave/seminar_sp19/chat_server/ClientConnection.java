package edu.capital.eave.seminar_sp19.chat_server;

public class ClientConnection {

	private String username;
	private ClientRequestHandler handler;
	private int sessionId;
	private boolean loggedIn = false;
	
	public ClientConnection(ClientRequestHandler requestHandler, int session) {
		this.setHandler(requestHandler);
		this.sessionId = session;
		
	}
	
	public int getSessionId() {
		return sessionId;
	}

	public String getUsername() {
		if(username != null)
			return username;
		else
			return "";
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public boolean isLoggedIn() {
		return loggedIn;
	}

	public void setLoggedIn(boolean loggedIn) {
		this.loggedIn = loggedIn;
	}

	public ClientRequestHandler getHandler() {
		return handler;
	}

	public void setHandler(ClientRequestHandler handler) {
		this.handler = handler;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) return false;
		if (obj == this) return true;
		if (!(obj instanceof ClientConnection)) return false;
		ClientConnection o = (ClientConnection) obj;
		return o.sessionId == this.sessionId;
	}

	@Override
	public int hashCode() {
		return sessionId;
	}
}
