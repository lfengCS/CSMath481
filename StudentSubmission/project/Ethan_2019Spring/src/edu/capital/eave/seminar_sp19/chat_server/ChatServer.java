package edu.capital.eave.seminar_sp19.chat_server;

import edu.capital.eave.seminar_sp19.chat_server.db.SimpleChatDatabase;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;

import edu.capital.eave.seminar_sp19.chat_client.Constants;

/**
 * An extremely basic multi-threaded chat server that uses a hybrid of AES/RSA
 * to encrypt messages between two users.
 *
 * TODO: User accounts/multiple chat windows
 * 
 * Reference: https://www.geeksforgeeks.org/multi-threaded-chat-application-set-1/
 * Reference: http://tutorials.jenkov.com/java-cryptography/cipher.html
 * @author Ethan Ave <eave@capital.edu>
 *
 */
public class ChatServer {

	/**
	 * Holds our list of active connections to the server
	 */
	public static ArrayList<ClientConnection> connections = new ArrayList<>();

	public static void main(String[] args) {

		ServerSocket serverSock = null;
		try {

			// The connectionId will increment every time somebody connects to the server to
			// give a unique session id to every connection.
			int connectionId = 0;
			serverSock = new ServerSocket(Constants.SERVER_PORT);
			System.out.println("Starting server on port " + serverSock.getLocalPort());

			// We want to repeatedly accept any new connections coming in
			Socket s;
			while(true) {
				s = serverSock.accept();
				System.out.println("New client request: " + s);

				// Create a new ClientRequestHandler thread to handle our user connection
				ClientRequestHandler handler = new ClientRequestHandler(s, connectionId);
				Thread thread = new Thread(handler);

				// Make sure our connection is in our active connections list
				connections.add(new ClientConnection(handler, connectionId));

				// Run our thread to handle the connection
				thread.start();

				connectionId++;// Increment session identifier
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				serverSock.close();
				SimpleChatDatabase.closeDB();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

	}

}
