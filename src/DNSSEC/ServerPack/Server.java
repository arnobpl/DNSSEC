package DNSSEC.ServerPack;

import DNSSEC.Common.RSA_Cryptography;

import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Created by arnob on 19/05/2017.
 * Server abstract class with all necessary methods
 */
public abstract class Server {
    // ---------- Configurable Data (start) ---------- //

    private static final String domainIpFilename = "domain_ip.csv";
    private static final int approximateDomainIpList = 250;

    public static final String rsa_Folder = "RSA_keyPair/";
    public static final String publicKeyFilename = "publicKey";
    private static final String privateKeyFilename = "privateKey";

    private static final int totalClientResponseThreads = 10;    // the number of limited client threads for the server

    public static final int port = 45678;

    // ---------- Configurable Data (end) ---------- //


    protected static RSA_Cryptography rsa;
    protected static PublicKey publicKey;
    protected static PrivateKey privateKey = null;

    protected static final List<DomainIp> domainIpList = new ArrayList<>(approximateDomainIpList);

    private ServerSocket serverSocket;

    // for maintaining limited client threads and also for performance reason (same threads are continuously used)
    private final ExecutorService clientResponseThreads = Executors.newFixedThreadPool(totalClientResponseThreads);

    private final BlockingQueue<Socket> clientSockets = new LinkedBlockingQueue<>(totalClientResponseThreads);

    private volatile boolean isRunning = false; // shared in more than one thread to stop server


    public Server() {
        readServerData();
        setupServer();
    }

    private void readServerData() {
        // check if already initialized
        if (privateKey != null) return;

        // clear invalid domainIp entries in case of failed server
        domainIpList.clear();

        // read domainIp data
        Scanner in = null;
        try {
            in = new Scanner(new File(domainIpFilename));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            System.exit(-100);  // fatal error, so terminate server
        }
        while (in.hasNextLine()) {
            String[] input = in.nextLine().split(",");
            if (input.length != 2) break;
            domainIpList.add(new DomainIp(input[0], input[1]));
        }
        in.close();
        Collections.sort(domainIpList, DomainIp.SORT_BY_DOMAIN);

        // read RSA keys
        try {
            rsa = new RSA_Cryptography();
            publicKey = rsa.getPublic(rsa_Folder + publicKeyFilename);
            privateKey = rsa.getPrivate(rsa_Folder + privateKeyFilename);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | IOException e) {
            e.printStackTrace();
        }
    }

    protected abstract void setupServer();

    public final void runServer() {
        // creating server socket
        try {
            serverSocket = new ServerSocket(port);
        } catch (IOException e) {
            e.printStackTrace();
            System.err.println("Please ensure that no other server is using the port " + Integer.toString(port));
            System.exit(-300);  // fatal error, so terminate server
        }

        // ready to run server
        isRunning = true;

        // running server in a separate thread so that 'runServer()' is not a blocking call
        new Thread(() -> {
            try {
                while (isRunning) {
                    clientSockets.put(serverSocket.accept());
                    clientResponseThreads.execute(() -> {
                        Socket client = null;
                        try {
                            // assign client connection
                            client = clientSockets.take();
                            Scanner in = new Scanner(new BufferedReader(new InputStreamReader(client.getInputStream())));
                            PrintWriter out = new PrintWriter(client.getOutputStream(), true);

                            // get and print client IP address
                            String clientIp = in.nextLine();
                            printLine();
                            System.out.println("Request from client: " + clientIp);
                            printLine();

                            boolean isConnected;
                            do {
                                // respond to client
                                respond(in, out, clientIp);

                                // check if connected
                                try {
                                    isConnected = in.hasNext();
                                } catch (IllegalStateException e) {
                                    isConnected = false;
                                }
                            } while (isConnected);

                            // print ending lines
                            printLine();
                            System.out.println();
                        } catch (IOException | InterruptedException e) {
                            e.printStackTrace();
                        } finally {
                            if (client != null) try {
                                client.close();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                    });
                }
            } catch (IOException | InterruptedException e) {
                e.printStackTrace();
            } finally {
                try {
                    serverSocket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }).start();

        System.out.println("Server started.");
    }

    /**
     * This method responses to individual client request.
     * No multithreading is needed here because it is already done by {@code Server}.
     * Also, it is not needed to close client socket after response because of the same above reason.
     *
     * @param in       input stream from client
     * @param out      output stream to client
     * @param clientIp
     */
    protected abstract void respond(Scanner in, PrintWriter out, String clientIp);

    public final int domainCount() {
        return domainIpList.size();
    }

    public final void stopServer() {
        isRunning = false;
        clientResponseThreads.shutdownNow();
        try {
            serverSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void printLine() {
        System.out.println("----------------------------------------");
    }


    /**
     * Class for containing domain and IP with sorting methods
     */
    protected static class DomainIp implements Comparator<DomainIp> {
        public final String domain;
        public final String ip;

        public static final SortByDomain SORT_BY_DOMAIN = new SortByDomain();
        public static final SortByIp SORT_BY_IP = new SortByIp();

        public DomainIp(String domain, String ip) {
            this.domain = domain;
            this.ip = ip;
        }

        @Override
        public int compare(DomainIp o1, DomainIp o2) {
            return SORT_BY_DOMAIN.compare(o1, o2);  // default sorting
        }

        private static class SortByDomain implements Comparator<DomainIp> {
            @Override
            public int compare(DomainIp o1, DomainIp o2) {
                return o1.domain.compareTo(o2.domain);
            }
        }

        private static class SortByIp implements Comparator<DomainIp> {
            @Override
            public int compare(DomainIp o1, DomainIp o2) {
                return o1.ip.compareTo(o2.ip);
            }
        }

        @Override
        public String toString() {
            return domain + "," + ip;
        }
    }
}
