import java.net.InetSocketAddress;
//class used if checking for duplicates
public class ReceivedPacket {

    public int packetIdentifier;


    public long receiveTime;


    public InetSocketAddress address;


    public byte[] authenticator;
}
