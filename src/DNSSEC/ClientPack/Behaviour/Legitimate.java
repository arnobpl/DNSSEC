package DNSSEC.ClientPack.Behaviour;

import DNSSEC.ClientPack.Client;
import DNSSEC.ServerPack.Security.NSEC;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.util.Scanner;

/**
 * Created by arnob on 21/05/2017.
 * Implementation of legitimate client
 */
public class Legitimate extends Client {
    public Legitimate(String clientIp) {
        super(clientIp);
    }

    @Override
    protected void setupClient() {
    }

    @Override
    protected void request(Scanner in, PrintWriter out) {
        // get domain name from console
        Scanner console_in = new Scanner(System.in);
        System.out.println("Enter a domain for request: ");
        String domain = console_in.nextLine();

        // send domain request and receive server response
        requestCore(in, out, domain);
    }

    /**
     * @return {@code Result} object if IP address or NSEC received, otherwise {@code null}
     */
    static Result requestCore(Scanner in, PrintWriter out, String domain) {
        // sending request to server
        out.println(domain);
        System.out.println("Request sent for: \"" + domain + "\"");

        // parsing server response
        String responseWholeLine = in.nextLine();
        String[] response = responseWholeLine.split(" ");

        // check if server message received instead of IP address or NSEC
        if (response.length > 3) {
            System.out.println("Server message: " + responseWholeLine);
            return null;
        }

        // check if NSEC received
        if (response.length == 3) {
            String header = response[0];
            System.out.println("Header: " + header);

            if (header.equals(NSEC.header)) {
                String[] domainRange = response[1].split(",");
                if (domainRange.length != 2) {
                    System.err.println("Invalid response from DNS server.");
                    return null;
                }

                // store received NSEC
                Result result = new Result(domain);
                result.domainStart = domainRange[0];
                result.domainEnd = domainRange[1];
                result.signature = response[2];
                result.isVerified = isVerified(domain, result.domainStart, result.domainEnd, result.signature);

                // print received NSEC
                System.out.println("Requested non-existing domain: " + domain);
                System.out.println("Domain range start: " + result.domainStart);
                System.out.println("Domain range end: " + result.domainEnd);
                System.out.println("Signature: " + result.signature);
                System.out.println("IsVerified: " + Boolean.toString(result.isVerified));

                // successful NSEC received
                return result;
            }
        }

        // check if invalid response received
        if (response.length != 2) {
            System.err.println("Invalid response from DNS server.");
            return null;
        }

        // IP address received for the requested domain
        System.out.println("Reply from Server:");
        String[] domainIpResponse = response[0].split(",");
        if (domainIpResponse.length != 2) {
            System.err.println("Invalid response from DNS server.");
            return null;
        }

        // store received IP address
        Result result = new Result(domainIpResponse[0]);
        result.ip = domainIpResponse[1];
        result.signature = response[1];
        result.isVerified = isVerified(domain, result.ip, result.signature);

        // print detailed info for the received IP address
        System.out.println("Domain: " + result.domain);
        System.out.println("IP: " + result.ip);
        System.out.println("Signature: " + result.signature);
        System.out.println("IsVerified: " + Boolean.toString(result.isVerified));

        // successful IP address received
        return result;
    }

    /**
     * This method is used in existing domain response verification.
     */
    private synchronized static boolean isVerified(String domain, String ip, String signature) {
        String message = domain + "," + ip;
        try {
            return Integer.toString(message.hashCode()).equals(rsa.getHashFromSignature(signature, publicKey));
        } catch (InvalidKeyException | UnsupportedEncodingException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * This method is used in non-existing domain response verification.
     */
    private synchronized static boolean isVerified(String domain, String domainRangeStart, String domainRangeEnd, String signature) {
        // check if domain in the range
        if (domain.compareTo(domainRangeStart) < 0 || domain.compareTo(domainRangeEnd) > 0)
            return false;

        // check signature against hashcode
        String message = domainRangeStart + "," + domainRangeEnd;
        try {
            return Integer.toString(message.hashCode()).equals(rsa.getHashFromSignature(signature, publicKey));
        } catch (InvalidKeyException | UnsupportedEncodingException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return false;
        }
    }


    /**
     * Class for storing server response for IP address or NSEC
     */
    static class Result {
        public String domain;
        public String ip = "";

        public String domainStart = "";
        public String domainEnd = "";

        public String signature = "";
        public boolean isVerified = false;

        public Result(String domain) {
            this.domain = domain;
        }
    }
}
