import DNSSEC.ClientPack.Behaviour.Attacker;
import DNSSEC.ServerPack.Security.LowProfiling;
import DNSSEC.ServerPack.Server;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.Random;

/**
 * Created by arnob on 19/07/2017.
 * Main class for automated test which runs both server and client
 */
public class AutomatedTest {
    // ---------- Configurable Data (start) ---------- //

    private static final String automatedTestFilename = "AutomatedTest/data.csv";

    private static final int totalAttackers = 250; // maximum 254 for IP address scheme
    private static final int totalTestIteration = 10;

    private static final String ipPrefix = "10.121.100.";

    private static final double minAttackNoise = 0.0;
    private static final double maxAttackNoise = 1.0;

    // ---------- Configurable Data (end) ---------- //


    private static final double attackNoiseRange = (maxAttackNoise - minAttackNoise);


    public static void main(String[] args) {
        // show automatic test start message
        System.out.println("Automatic Test started..........");

        // create file for print
        PrintWriter fileOut;
        try {
            fileOut = new PrintWriter(new File(automatedTestFilename));
            fileOut.println("AttackNoise,DomainFetched,AttackCoverage,AttackRuntime (msec),AttackSpeed (domain per msec)");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            System.err.println("Automated test file cannot be created.");
            return;
        }

        for (int it = 0; it < totalTestIteration; it++) {
            // run server
            Server server = new LowProfiling();
            server.runServer();
            waitForMoment(); // wait for server to be ready

            // run attacker clients
            final Random random = new Random();
            Attacker[] attackers = new Attacker[totalAttackers];
            for (int i = 0; i < totalAttackers; i++) {
                Attacker attacker = new Attacker(ipPrefix + Integer.toString(i + 1),
                        (minAttackNoise + (random.nextDouble() * attackNoiseRange)),
                        true);
                attacker.runClient();
                attackers[i] = attacker;
            }

            // print result
            final double domainCount = server.domainCount();
            for (int i = 0; i < totalAttackers; i++) {
                Attacker attacker = attackers[i];
                if (!attacker.isFinished()) {
                    i--;
                    waitForMoment();
                    continue;
                }

                int domainFetched = attacker.domainFetched();
                fileOut.println(Double.toString(attacker.attackNoise()) + "," +
                        Integer.toString(domainFetched) + "," +
                        Double.toString((double) domainFetched / domainCount) + "," +
                        Long.toString(attacker.attackRuntime()) + "," +
                        Double.toString((double) domainFetched / attacker.attackRuntime()));
            }

            // stop server
            server.stopServer();
        }

        // close test file
        fileOut.close();

        // show automatic test end message
        System.out.println("Automatic Test finished..........");
    }

    private static void waitForMoment() {
        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
