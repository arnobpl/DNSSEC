import DNSSEC.ClientPack.Behaviour.Attacker;
import DNSSEC.ClientPack.Client;

/**
 * Created by arnob on 13/06/2017.
 * Main Class for Client
 */
public class ClientMain {
    public static void main(String[] args) {
        //Client client = new Legitimate("10.121.100.5");
        Client client = new Attacker("10.121.100.5");
        client.runClient();
    }
}
