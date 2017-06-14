package DNSSEC.ServerPack.Security;

import DNSSEC.Common.NetworkTask;
import DNSSEC.ServerPack.Server;

import java.io.PrintWriter;
import java.util.*;

/**
 * Created by arnob on 19/05/2017.
 * Implementation of Low Profiling
 */
public class LowProfiling extends Server {
    // ---------- Configurable Data (start) ---------- //

    private static final long oldRecordCleanupTimeElapsed = 300000; // in millisecond

    private static final int maxSuspiciousRecordsForEachClient = 10;
    private static final long suspiciousClientBlockTimeElapsed = 120000;    // in millisecond

    // ---------- Configurable Data (end) ---------- //


    private Map<String, Activity> clientRecordMap;


    @Override
    public void setupServer() {
        NSEC.initialize();

        clientRecordMap = new HashMap<>();
    }

    @Override
    protected void respond(Scanner in, PrintWriter out, String clientIp) {
        // get and print client's requested domain name
        String domain = in.nextLine();
        System.out.println("Request string: " + domain);

        // check if client request is legitimate
        if (isRequestLegitimate(clientIp, domain, out)) {
            // respond to the client
            NSEC.respondCore(in, out, domain);
        }

        System.out.println();
    }

    /**
     * This method checks if client request is legitimate.
     * If not legitimate, it also notifies the suspicious client.
     */
    private boolean isRequestLegitimate(String clientIp, String domain, PrintWriter out) {
        // check if valid client IP address
        if (!NetworkTask.isValid_IP4_address(clientIp)) {
            out.println("Client IP address is not valid.");
            System.out.println("Response sent for invalid client IP address.");
            return false;
        }

        // get the activity corresponding to the client IP address
        Activity activity = clientRecordMap.get(clientIp);
        if (activity == null) {
            activity = new Activity();
            clientRecordMap.put(clientIp, activity);
        }

        // check if client request suspicious
        if (activity.isSuspicious(domain)) {
            out.println("This client IP address is blocked for suspicious activity. Please try later.");
            System.out.println("Response sent for being blocked for suspicious activity.");
            return false;
        }

        // request is legitimate
        return true;
    }


    private static class Activity {
        private LinkedList<Record> requestRecords = new LinkedList<>();

        private boolean isSuspicious = false;
        private long blockTime;

        public boolean isSuspicious(String domain) {
            long currentTime = System.currentTimeMillis();

            // check if already suspicious activity found and within block time period
            if (isSuspicious && ((currentTime - blockTime) < suspiciousClientBlockTimeElapsed)) return true;

            // clear suspicious status
            isSuspicious = false;

            // cleanup old request records
            cleanupOldRecords();

            // check if suspicious
            if (!requestRecords.isEmpty()) {
                Record lastRecord = requestRecords.getLast();

                // check if requested domain breaks lexicographical order (not suspicious)
                if (lastRecord.domain.compareTo(domain) >= 0) {
                    requestRecords.clear();
                }
                // check if previous requests in lexicographical order exceeds the constant (suspicious)
                else if (requestRecords.size() >= maxSuspiciousRecordsForEachClient) {
                    isSuspicious = true;
                    requestRecords.removeFirst();
                }
            }

            // add domain request to activity record
            Record record = new Record(domain);
            requestRecords.add(record);

            // assign blockTime (if suspicious) and return result
            blockTime = currentTime;
            return isSuspicious;
        }

        private void cleanupOldRecords() {
            long currentTime = System.currentTimeMillis();
            for (Iterator<Record> iterator = requestRecords.iterator(); iterator.hasNext(); ) {
                Record record = iterator.next();
                if ((currentTime - record.time) >= oldRecordCleanupTimeElapsed) {
                    iterator.remove();
                } else {
                    break;
                }
            }
        }


        private static class Record {
            public String domain;
            public long time;

            public Record(String domain) {
                this.domain = domain;
                this.time = System.currentTimeMillis();
            }
        }
    }
}

