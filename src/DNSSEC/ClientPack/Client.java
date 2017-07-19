package DNSSEC.ClientPack;

import DNSSEC.Common.RSA_Cryptography;
import DNSSEC.ServerPack.Server;

import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

/**
 * Created by arnob on 21/05/2017.
 * Client abstract class with all necessary methods
 */
public abstract class Client {
    // ---------- Configurable Data (start) ---------- //

    public static final String serverIp = "127.0.0.1";

    // ---------- Configurable Data (end) ---------- //


    protected String clientIp;

    protected static RSA_Cryptography rsa;
    protected static PublicKey publicKey = null;

    private Socket socket;
    private Scanner in;
    private PrintWriter out;

    private volatile boolean isFinished = false;


    public Client(String clientIp) {
        this.clientIp = clientIp;
        readClientData();
        setupClient();
    }

    private void readClientData() {
        // check if already initialized
        if (publicKey != null) return;

        // read RSA public key
        try {
            rsa = new RSA_Cryptography();
            publicKey = rsa.getPublic(Server.rsa_Folder + Server.publicKeyFilename);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | IOException e) {
            e.printStackTrace();
        }
    }

    protected abstract void setupClient();

    /**
     * This method runs client in a new thread.
     * There is no {@code stopClient} method because client with all sockets is automatically terminated
     * after executing {@code request(Scanner in, PrintWriter out, Socket socket)}.
     */
    public final void runClient() {
        try {
            socket = new Socket(serverIp, Server.port);
            in = new Scanner(new BufferedReader(new InputStreamReader(socket.getInputStream())));
            out = new PrintWriter(socket.getOutputStream(), true);
            new Thread(() -> {
                // send client IP address
                out.println(clientIp);
                // print server IP address
                Server.printLine();
                System.out.println("Request to server: " + serverIp);
                Server.printLine();

                // send client request
                request(in, out);

                // print ending lines
                Server.printLine();
                System.out.println();
                try {
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }

                // change isFinished flag
                isFinished = true;
            }).start();
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(-100);  // fatal error, so terminate client
        }

        System.out.println("Client started.");
    }

    /**
     * This method interacts with server by domain request.
     * It also incorporates client's behaviour (eg. legitimate or attacker client).
     * It is not needed to close socket after request because it is already done by {@code Client}.
     */
    protected abstract void request(Scanner in, PrintWriter out);

    /**
     * @return {@code true} if the client finishes its request, otherwise {@code false}
     */
    public final boolean isFinished() {
        return isFinished;
    }
}
