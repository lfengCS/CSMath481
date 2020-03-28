package edu.capital.eave.seminar_sp19.chat_server.db;

import java.math.BigInteger;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import edu.capital.eave.seminar_sp19.RSA;

/**
 * A very simple static database connection to our mySQL database
 *
 * @author Ethan Ave {@literal <eave@capital.edu>}
 */
public class SimpleChatDatabase {

	public static Connection connection;

	public static Connection getConnection() {

		// Connect if we haven't yet
		if(connection == null)
			connectToDB();

		return connection;
	}

	public static void closeDB() {
		try {
			connection.close();
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

	public static void connectToDB() {
		try {
			connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/chat_test?useJDBCCompliantTimezoneShift=true&useLegacyDatetimeCode=false&serverTimezone=UTC", "root", "");
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		System.out.println(SimpleChatDatabase.getPublicKey("chris"));
	}

	public static BigInteger getPublicKey(String user) {
		Connection connection = SimpleChatDatabase.getConnection();
		Statement st = null;
		try {
			   String query = "SELECT PUBLIC_KEY FROM users WHERE USERNAME=?";
			   st = connection.createStatement();
			   PreparedStatement ps = connection.prepareStatement(query);
			   ps.setString(1, user);
			   
			   ResultSet rs = ps.executeQuery();
			   while (rs.next()) {
				   byte[] pubMod = rs.getBytes("PUBLIC_KEY");
				   BigInteger test = new BigInteger(pubMod);
				   return test;
			   }
		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
			try {
				st.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
		return null;
	}

	// Used to create a new user in the database since we have no account creation system yet
	public static void main9(String[] args) {
		
		
		RSA randomKey = new RSA(4096);
		
		// Create original database
		Connection connection = null;
		Statement st = null;
		try {
			connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/chat_test?useJDBCCompliantTimezoneShift=true&useLegacyDatetimeCode=false&serverTimezone=UTC", "root", "");
			   String query = "INSERT INTO users (USERNAME, IP_ADDRESS, PUBLIC_KEY, ID) VALUES (?, ?, ?, ?)";
			   
			   st = connection.createStatement();
			   PreparedStatement pstat = connection.prepareStatement(query);
			   pstat.setString(1, "ethan");
			   pstat.setString(2, "75.188.113.5");
			   pstat.setBytes(3, randomKey.publicBytes());
			   pstat.setInt(4, 0);
			   pstat.execute();
		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
			try {
				st.close();
				connection.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
	}
}
