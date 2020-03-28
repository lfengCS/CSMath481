package edu.capital.eave.seminar_sp19.chat_client;

import java.math.BigInteger;

public class Constants {
    /**
     * We use 65537 as our public exponent because it is large enough to
     * still be fast, but provides some protection against vulnerability caused
     * when e is too small AND improper padding is used. It should be noted that
     * a small e does not in and of itself cause vulnerability, and would be the
     * result of a poorly/improperly implemented padding algorithm but we use
     * a relatively large e to prevent against unknown vulnerabilities.
     */
    public static final BigInteger PUBLIC_EXPONENT = BigInteger.valueOf(65537);

    /**
     * The port that the server will run on and that the client needs to use
     * to connect to the server.
     */
    public static final int SERVER_PORT = 15999;

    /**
     * The IP address the server will run on
     */
    public static final String SERVER_IP = "localhost";

    /**
     * For easy switching between accounts since we do not have
     * a proper account system yet
     */
    public static final boolean USE_USER_ETHAN = false;
}
