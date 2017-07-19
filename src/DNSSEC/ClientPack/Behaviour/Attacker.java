package DNSSEC.ClientPack.Behaviour;

import DNSSEC.ClientPack.Client;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.Random;
import java.util.Scanner;

/**
 * Created by arnob on 21/05/2017.
 * Implementation of attacker client
 */
public class Attacker extends Client {
    // ---------- Configurable Data (start) ---------- //

    private static final String attackerFilename = "Attacker/attackerFile.txt";

    private static final String attackStoppedMessage = "Server might have detected the attack or record might have reached to the end.";

    private static final char firstCharForAttacker = '0';
    private static final char lastCharForAttacker = 'z';

    // ---------- Configurable Data (end) ---------- //


    private static final Random random = new Random();

    private volatile int domainFetched = 0;

    private long startTime; // start time of attack
    private volatile long attackRuntime = 0L; // attack runtime in milliseconds

    private final double attackNoise; // attack noise so that DNS server hardly detect the attack
    private final boolean isAutomatedTest;


    public Attacker(String clientIp, double attackNoise, boolean isAutomatedTest) {
        super(clientIp);
        this.attackNoise = attackNoise;
        this.isAutomatedTest = isAutomatedTest;
    }

    @Override
    protected void setupClient() {
    }

    @Override
    protected void request(Scanner in, PrintWriter out) {
        startTime = System.currentTimeMillis();

        String domain;
        if (isAutomatedTest) {
            // assign initial probable non-existing domain
            domain = String.valueOf(firstCharForAttacker);
        } else {
            // get domain name from console
            Scanner console_in = new Scanner(System.in);
            System.out.println("Enter a non-existing domain to start attack: ");
            domain = console_in.nextLine();
        }

        // create attacker's file to store server data
        PrintWriter fileOut = null;
        if (!isAutomatedTest) {
            try {
                fileOut = new PrintWriter(new File(attackerFilename));
            } catch (FileNotFoundException e) {
                e.printStackTrace();
                System.err.println("Attacker's file cannot be created.");
                return;
            }
        }

        // send first non-existing domain request and receive server response
        Legitimate.Result result = sendRequest(in, out, domain);

        while (result != null) {
            if (!result.ip.isEmpty()) {
                System.out.println("Unexpected valid IP address found and so attack stopped.");
                return;
            }

            // assign valid domain for request
            domain = result.domainEnd;

            // send existing domain request and receive server response
            result = sendRequest(in, out, domain);
            if (result == null) {
                stopAttack(fileOut);
                return;
            } else {
                if (!isAutomatedTest) {
                    // store domain info into attacker's file
                    fileOut.println(domain + " " + result.ip + " " + result.signature);
                    fileOut.println();
                }
                domainFetched++;
            }

            // depending on probability, send previous possible non-existing domain
            if (shouldSendPreviousDomain()) sendRequest(in, out, previousString(domain));

            // assign next possible non-existing domain
            domain = nextString(domain);

            // send next non-existing domain request and receive server response
            result = sendRequest(in, out, domain);
        }

        stopAttack(fileOut);
    }


    private static Legitimate.Result sendRequest(Scanner in, PrintWriter out, String domain) {
        Legitimate.Result result = Legitimate.requestCore(in, out, domain);
        System.out.println();
        return result;
    }


    private static String nextString(String currentString) {
        StringBuilder stringBuilder = new StringBuilder(currentString);
        int length = stringBuilder.length();
        char lastChar = stringBuilder.charAt(length - 1);
        if (lastChar < lastCharForAttacker) {
            lastChar++;
            stringBuilder.setCharAt(length - 1, lastChar);
        } else {
            stringBuilder.append(firstCharForAttacker);
        }
        return stringBuilder.toString();
    }

    private static String previousString(String currentString) {
        StringBuilder stringBuilder = new StringBuilder(currentString);
        int length = stringBuilder.length();
        char lastChar = stringBuilder.charAt(length - 1);
        if (lastChar > firstCharForAttacker) {
            lastChar--;
            stringBuilder.setCharAt(length - 1, lastChar);
        } else {
            if (length > 1) stringBuilder.setLength(length - 1);
            else stringBuilder.setCharAt(0, firstCharForAttacker);
        }
        return stringBuilder.toString();
    }


    private boolean shouldSendPreviousDomain() {
        return (random.nextDouble() < attackNoise);
    }


    private void stopAttack(PrintWriter fileOut) {
        if (!isAutomatedTest) fileOut.close();
        System.out.println(attackStoppedMessage);
        System.out.println();
        attackRuntime = System.currentTimeMillis() - startTime;
    }


    public int domainFetched() {
        return domainFetched;
    }

    public long attackRuntime() {
        return attackRuntime;
    }

    public double attackNoise() {
        return attackNoise;
    }
}
