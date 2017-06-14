import DNSSEC.ServerPack.Security.LowProfiling;
import DNSSEC.ServerPack.Server;

/**
 * Created by arnob on 13/06/2017.
 * Main Class for Server
 */
public class ServerMain {
    public static void main(String[] args) {
        //Server server = new NSEC();
        Server server = new LowProfiling();
        server.runServer();
    }
}
