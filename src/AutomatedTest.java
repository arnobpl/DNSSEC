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

    private static final String automatedTestFolder = "AutomatedTest";
    private static final String automatedTestFilenameAttacker = "data_attacker.csv";
    private static final String automatedTestFilenameServer = "data_server.csv";

    private static final int fixedTotalSuspiciousRecordsForEachClient = 10;
    private static final int minTotalSuspiciousRecordsForEachClient = 5;
    private static final int maxTotalSuspiciousRecordsForEachClient = 50;
    private static final int totalTestIterationServer = 2500;

    private static final int totalAttackers = 250; // maximum 254 for IP address scheme
    private static final int totalTestIterationAttacker = 10;

    private static final String ipPrefix = "10.121.100.";

    private static final double fixedAttackNoise = 0.5;
    private static final double minAttackNoise = 0.0;
    private static final double maxAttackNoise = 1.0;

    // ---------- Configurable Data (end) ---------- //


    private static final double attackNoiseRange = (maxAttackNoise - minAttackNoise);
    private static final int totalSuspiciousRecordsForEachClientRange = (maxTotalSuspiciousRecordsForEachClient - minTotalSuspiciousRecordsForEachClient);

    private static final Random random = new Random();


    public static void main(String[] args) {
        // show automatic test start message
        System.out.println("Automatic Test started..........");

        // test attacker
        testAttacker();

        // test server
        testServer();

        // show automatic test end message
        System.out.println("Automatic Test finished..........");
    }


    private static void testAttacker() {
        // show test message
        System.out.println("Testing attacker");

        // create file for print
        PrintWriter fileOut;
        try {
            fileOut = new PrintWriter(new File(automatedTestFolder + "/" + automatedTestFilenameAttacker));
            fileOut.println("AttackNoise,DomainFetched,AttackCoverage,AttackRuntime (msec),AttackSpeed (domain per msec)");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            System.err.println("Automated test for attacker file cannot be created.");
            return;
        }

        for (int it = 0; it < totalTestIterationAttacker; it++) {
            // run server
            Server server = new LowProfiling(fixedTotalSuspiciousRecordsForEachClient);
            server.runServer();
            waitForMoment(); // wait for server to be ready

            // run attacker clients
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
    }

    private static void testServer() {
        // show test message
        System.out.println("Testing server");

        // create file for print
        PrintWriter fileOut;
        try {
            fileOut = new PrintWriter(new File(automatedTestFolder + "/" + automatedTestFilenameServer));
            fileOut.println("TotalSuspiciousRecords,DomainFetched,AttackCoverage,AttackRuntime (msec),AttackSpeed (domain per msec)");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            System.err.println("Automated test file for client cannot be created.");
            return;
        }

        for (int it = 0; it < totalTestIterationServer; it++) {
            // run server
            final int totalSuspiciousRecordsForEachClient = minTotalSuspiciousRecordsForEachClient + random.nextInt(totalSuspiciousRecordsForEachClientRange);
            Server server = new LowProfiling(totalSuspiciousRecordsForEachClient);
            server.runServer();
            waitForMoment(); // wait for server to be ready

            // run attacker client
            Attacker attacker = new Attacker(ipPrefix + "1", fixedAttackNoise, true);
            attacker.runClient();

            while (!attacker.isFinished()) {
                waitForMoment();
            }

            // print result
            final double domainCount = server.domainCount();
            int domainFetched = attacker.domainFetched();
            fileOut.println(Integer.toString(totalSuspiciousRecordsForEachClient) + "," +
                    Integer.toString(domainFetched) + "," +
                    Double.toString((double) domainFetched / domainCount) + "," +
                    Long.toString(attacker.attackRuntime()) + "," +
                    Double.toString((double) domainFetched / attacker.attackRuntime()));

            // stop server
            server.stopServer();
        }

        // close test file
        fileOut.close();
    }


    private static void waitForMoment() {
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
