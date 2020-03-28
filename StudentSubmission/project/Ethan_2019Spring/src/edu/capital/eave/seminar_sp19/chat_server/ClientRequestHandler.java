package edu.capital.eave.seminar_sp19.chat_server;

import edu.capital.eave.seminar_sp19.chat_client.ClientPackets;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.Arrays;

public class ClientRequestHandler implements Runnable  {

	public ClientRequestHandler(Socket s, int connectionId) {
		this.s = s;
		this.sessionId = connectionId;
		try {
			this.outputStream = new DataOutputStream(s.getOutputStream());
			this.inputStream = new DataInputStream(s.getInputStream());
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}
	
	private Socket s;
	private int sessionId;
	private DataOutputStream outputStream;
	private DataInputStream inputStream;
	private ClientConnection currentConnection = null;
	
	
	@Override
	public void run() {

		// In this thread we repeatedly loop to see if packets are
		// coming in from this user
		packet_loop: while(true) {
			try {

				if(inputStream.available() > 0) {
					int packetId = inputStream.readInt();
					
					//Log in packet
					if(packetId == ServerPackets.LOGIN) {
						String username = inputStream.readUTF();
						boolean alreadyLoggedIn = false;
						
						// Since we have no passwords on our accounts we
						// just need to check if we're already logged in
						// and if not set this username to logged in
						for(ClientConnection conn : ChatServer.connections) {
							if(conn.getUsername().equals(username)) {
					
								if(conn.isLoggedIn()) {
									System.err.println("User " + username + " already logged in with pid " + conn.getSessionId() + "!");
									alreadyLoggedIn = true;
								}
							}
						}
						
						// If we're not logged in already, we need to find our current connection
						// in our connections arraylist and set the username and login status

						for(ClientConnection conn : ChatServer.connections) {

							if(conn.getSessionId() == sessionId) {

								// If we are already logged in we should remove the connection
								// and exit immediately
								if(alreadyLoggedIn) {
									writeFatalErrorMessage("User already logged in!");
									s.close();
									ChatServer.connections.remove(conn);
									break packet_loop;
								}

								// If not we can set our connection's username/login status
								conn.setUsername(username);
								conn.setLoggedIn(true);
								currentConnection = conn;

								System.out.println("User " + username + " has logged in!");
							}
						}
					} else if(packetId == ServerPackets.SEND_MESSAGE) {// User is attempting to send a message

						// Read in our message data
						String recipient = inputStream.readUTF();
						int ivLength = inputStream.readInt();
						int cipherTextLength = inputStream.readInt();
						int encryptedSecretKeyLength = inputStream.readInt();
						byte[] iv = new byte[ivLength];
						byte[] cipherText = new byte[cipherTextLength];
						byte[] encSecretKey = new byte[encryptedSecretKeyLength];
						inputStream.read(iv);
						inputStream.read(cipherText);
						inputStream.read(encSecretKey);


						// Send our message data to the recipient if they are online
						if(currentConnection != null) {
							
							for(ClientConnection conn : ChatServer.connections) {
								if(conn.getUsername().equals(recipient)) {
									conn.getHandler().sendEncryptedMessage(currentConnection.getUsername(), iv, cipherText, encSecretKey);
								}
							}
							System.out.println(currentConnection.getUsername() + " attempting to send message to " + recipient);
							System.out.println("Sending RSA encrypted secret key: " + Arrays.toString(encSecretKey));
							System.out.println("Sending AES encrypted ciphertext: " + Arrays.toString(cipherText));
						}
					} else if(packetId == ServerPackets.LOGOUT) {
						if(currentConnection != null) {
							System.out.println("User " + currentConnection.getUsername() + " has logged out!");
							ChatServer.connections.remove(currentConnection);
							currentConnection = null;
							s.close();
							break;
						}
					}
				
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
	}

	/**
	 * Tells the client to display an error message and then close the client connection.
	 * 
	 * @param mes The message we want to send before the connection is closed.
	 */
	private void writeFatalErrorMessage(String mes) {
		try {
			outputStream.writeInt(ClientPackets.FATAL_ERROR_MESSAGE);
			outputStream.writeUTF(mes);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}


	private void sendEncryptedMessage(String fromUser, byte[] iv, byte[] cipherText, byte[] encSecretKey) {
		if(currentConnection != null) {
			try {
				outputStream.writeInt(ClientPackets.SEND_ENC_USER_MESSAGE);
				outputStream.writeUTF(fromUser);
				outputStream.writeInt(iv.length);
				outputStream.writeInt(cipherText.length);
				outputStream.writeInt(encSecretKey.length);
				outputStream.write(iv);
				outputStream.write(cipherText);
				outputStream.write(encSecretKey);
			} catch (IOException e) {
				e.printStackTrace();
			}
			
		}
	}
}
