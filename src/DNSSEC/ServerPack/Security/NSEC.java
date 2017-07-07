package DNSSEC.ServerPack.Security;

import DNSSEC.ServerPack.Server;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * Created by arnob on 19/05/2017.
 * Implementation of NSEC
 */
public class NSEC extends Server {
    public static final String header = "NSEC";

    public static final String startDomainBound = "!";
    public static final String endDomainBound = "~";

    // domain-DomainIpSignature mapping for faster detection and response
    static Map<String, DomainIpSignature> domainIpSignatureMap = null;

    // store only domains for non-existed domain response certificates
    static List<String> domainList;

    // store non-existed domain response certificates
    static List<String> nonExistedDomainCerts;


    @Override
    public void setupServer() {
        initialize();
    }

    static void initialize() {
        // check if already initialized
        if (domainIpSignatureMap != null) return;

        // assign new objects
        domainIpSignatureMap = new HashMap<>(domainIpList.size());
        domainList = new ArrayList<>(domainIpList.size() + 2);
        nonExistedDomainCerts = new ArrayList<>(domainIpList.size() + 1);

        // create domain-DomainIpSignature mapping
        domainList.add(startDomainBound);
        for (DomainIp domainIp : domainIpList) {
            try {
                String signature = rsa.getSignatureFromHash(Integer.toString(domainIp.toString().hashCode()), privateKey);
                domainIpSignatureMap.put(domainIp.domain, new DomainIpSignature(domainIp, signature));
                domainList.add(domainIp.domain);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | UnsupportedEncodingException | InvalidKeyException | BadPaddingException e) {
                e.printStackTrace();
            }
        }
        domainList.add(endDomainBound);

        // create NSEC certificates
        int iterateEnd = domainList.size() - 1;
        for (int i = 0; i < iterateEnd; i++) {
            try {
                String hashString = Integer.toString((domainList.get(i) + "," + domainList.get(i + 1)).hashCode());
                String signature = rsa.getSignatureFromHash(hashString, privateKey);
                nonExistedDomainCerts.add(signature);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | UnsupportedEncodingException | InvalidKeyException | BadPaddingException e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    protected void respond(Scanner in, PrintWriter out, String clientIp) {
        // get and print client's requested domain name
        String domain = in.nextLine();
        System.out.println("Request string: " + domain);

        // respond to the client
        respondCore(in, out, domain);

        System.out.println();
    }

    static void respondCore(Scanner in, PrintWriter out, String domain) {
        // check if domain name exists in domainIp list
        DomainIpSignature domainIpSignature = domainIpSignatureMap.get(domain);

        // handle request for existing domain
        if (domainIpSignature != null) {
            String response = domainIpSignature.domainIp.toString() + " " + domainIpSignature.signature;
            out.println(response);
            System.out.println("Response sent to client: " + response);
            return;
        }

        // handle invalid characters (may happens) and probable invisible characters (very very rare case)
        if ((domain.indexOf(',') != -1 || domain.indexOf(' ') != -1)
                || (domain.compareTo(startDomainBound) <= 0 || domain.compareTo(endDomainBound) >= 0)) {
            out.println("Request is completely invalid: probable invisible character found.");
            System.out.println("Response sent for probable invisible character.");
            return;
        }

        // handle NSEC
        out.print(header + " ");
        int signatureIndex = -Collections.binarySearch(domainList, domain) - 2;
        String response = domainList.get(signatureIndex) +
                "," + domainList.get(signatureIndex + 1) +
                " " + nonExistedDomainCerts.get(signatureIndex);
        out.println(response);
        System.out.println("Response sent to client for NSEC: " + response);
    }

    private static class DomainIpSignature {
        public final DomainIp domainIp;
        public final String signature;

        public DomainIpSignature(DomainIp domainIp, String signature) {
            this.domainIp = domainIp;
            this.signature = signature;
        }
    }
}
