package DNSSEC.Common;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by arnob on 13/06/2017.
 * Class for some network tasks
 */
public class NetworkTask {
    private static final String validIP4Pattern = "^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])$";
    private static final Pattern pattern = Pattern.compile(validIP4Pattern);

    public static boolean isValid_IP4_address(String ip4Address) {
        Matcher matcher = pattern.matcher(ip4Address);
        return matcher.matches();
    }
}
