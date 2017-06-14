package DNSSEC.ClientPack.Behaviour;

import DNSSEC.ClientPack.Client;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.Scanner;

/**
 * Created by arnob on 21/05/2017.
 * Implementation of attacker client
 */
public class Attacker extends Client {
    // ---------- Configurable Data (start) ---------- //

    public static final String attackerFilename = "Attacker/attackerFile.txt";

    public static final String attackStoppedMessage = "Server might have detected the attack or record might have reached to the end.";

    // ---------- Configurable Data (end) ---------- //


    public Attacker(String clientIp) {
        super(clientIp);
    }

    @Override
    protected void setupClient() {
    }

    @Override
    protected void request(Scanner in, PrintWriter out) {
        // get domain name from console
        Scanner console_in = new Scanner(System.in);
        System.out.println("Enter a non-existing domain to start attack: ");
        String domain = console_in.nextLine();

        // create attacker's file to store server data
        PrintWriter fileOut = null;
        try {
            fileOut = new PrintWriter(new File(attackerFilename));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            System.err.println("Attacker's file cannot be created.");
            return;
        }

        // send first non-existing domain request and receive server response
        Legitimate.Result result = Legitimate.requestCore(in, out, domain);
        System.out.println();

        while (result != null) {
            if (!result.ip.isEmpty()) {
                System.out.println("Unexpected valid IP address found and so attack stopped.");
                return;
            }

            // assign valid domain for request
            domain = result.domainEnd;

            // send existing domain request and receive server response
            result = Legitimate.requestCore(in, out, domain);
            System.out.println();
            if (result == null) {
                stopAttack(fileOut);
                return;
            } else {
                // store domain info into attacker's file
                fileOut.println(domain + " " + result.ip + " " + result.signature);
                fileOut.println();
            }

            // assign next possible non-existing domain
            domain = nextString(domain);

            // send next non-existing domain request and receive server response
            result = Legitimate.requestCore(in, out, domain);
            System.out.println();
        }

        stopAttack(fileOut);
    }

    private static String nextString(String currentString) {
        StringBuilder stringBuilder = new StringBuilder(currentString);
        char lastChar = stringBuilder.charAt(stringBuilder.length() - 1);
        if (lastChar != 'z') {
            lastChar++;
            stringBuilder.setCharAt(stringBuilder.length() - 1, lastChar);
        } else {
            stringBuilder.append('0');
        }
        return stringBuilder.toString();
    }

    private static void stopAttack(PrintWriter fileOut) {
        fileOut.close();
        System.out.println(attackStoppedMessage);
        System.out.println();
    }
}
