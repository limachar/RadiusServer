import Data.UserStorage;
import Model.User;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.tinyradius.packet.AccessRequest;
import org.tinyradius.packet.AccountingRequest;
import org.tinyradius.packet.RadiusPacket;
import org.tinyradius.util.RadiusException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.*;

public class RadiusServer extends org.tinyradius.util.RadiusServer  {
    //set address to listen to
    private InetAddress listenAddress;
    private int authPort = 1812;
    private DatagramSocket authSocket = null;
    protected boolean closing = false;
    private static Log logger = LogFactory.getLog(RadiusServer.class);
    private UserStorage userStorage;


    @Override
    public void setAuthPort(int authPort) {
        super.setAuthPort(authPort);
    }

    @Override
    public int getAuthPort() {
        return super.getAuthPort();
    }


    @Override
    public String getSharedSecret(InetSocketAddress client) {
        if (client.getAddress().getHostAddress().equals("127.0.0.1")) {
            return "1234567890";
        }
        return null;
    }

    @Override
    public String getUserPassword(String userName) {
        try {
            User u = userStorage.getUser(userName);
            return u.getPassword();
        }catch (NullPointerException e){
            return null;
        }

    }

    protected DatagramSocket getAuthSocket()
            throws SocketException {
        if (authSocket == null) {
            if (getListenAddress() == null)
                authSocket = new DatagramSocket(getAuthPort());
            else
                authSocket = new DatagramSocket(getAuthPort(), getListenAddress());
            authSocket.setSoTimeout(getSocketTimeout());
        }
        return authSocket;
    }

    protected void listen(final DatagramSocket socket) {
        //Receive packet
        while (true) {
            while (true) {
                try {
                    //creates DatagramPacket with maximum size 4096 bytes
                    final DatagramPacket packetIn = new DatagramPacket(new byte[4096], 4096);

                    try {
                        //Receives a datagram (packetIn) from (this) socket. Fills buffer with received data.
                        socket.receive(packetIn);

                    } catch (SocketException var4) {
                        if (closing) {
                            //ends listening on thread
                            return;
                        }

                        logger.error("SocketException during socket.receive() -> retry", var4);
                        continue;
                    }

                    if (executor == null) {
                        //check client
                        processRequest(socket, packetIn);
                    } else {
                        executor.submit(() -> processRequest(socket, packetIn));
                    }
                } catch (SocketTimeoutException var5) {
                    logger.trace("normal socket timeout");
                } catch (IOException var6) {
                    logger.error("communication error", var6);
                }
            }
        }
    }

    protected void processRequest(DatagramSocket s, DatagramPacket packetIn) {
        //checks client
        try {
            InetSocketAddress localAddress = (InetSocketAddress) s.getLocalSocketAddress();
            InetSocketAddress remoteAddress = new InetSocketAddress(packetIn.getAddress(), packetIn.getPort());
            //not sure about this. removed , makeRadiusPacket(packetIn, "1234567890", 255)
            String secret = getSharedSecret(remoteAddress);

            if (secret == null) {
                if (logger.isInfoEnabled()) {
                    logger.info("ignoring packet from unknown client " + remoteAddress + " received on local address " + localAddress);
                }

                return;
            }
            //parse packet
            RadiusPacket request = makeRadiusPacket(packetIn, secret);
            if (logger.isInfoEnabled()) {
                logger.info("received packet from " + remoteAddress + " on local address " + localAddress + ": " + request);
            }
            //handle packet
            logger.trace("about to call RadiusServer.handlePacket()");
            RadiusPacket response = handlePacket(localAddress, remoteAddress, request, secret);

            //send response
            if (response != null) {
                if (logger.isInfoEnabled()) {
                    logger.info("send response: " + response);
                }
                //uses same port and address so send back response
                DatagramPacket packetOut = this.makeDatagramPacket(response, secret, remoteAddress.getAddress(), packetIn.getPort(), request);
                //socket sends new DatagramPacket built from RadiusPackage object
                // after handling package and verifying password
                s.send(packetOut);
            } else {
                logger.info("no response sent");
            }
        } catch (IOException var9) {
            logger.error("communication error", var9);
        } catch (RadiusException var10) {
            logger.error("malformed Radius packet", var10);
        }

    }



    protected DatagramPacket makeDatagramPacket(RadiusPacket packet, String secret, InetAddress address, int port, RadiusPacket request) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        packet.encodeResponsePacket(bos, secret, request);
        byte[] data = bos.toByteArray();

        DatagramPacket datagram = new DatagramPacket(data, data.length, address, port);
        return datagram;
    }

    protected RadiusPacket makeRadiusPacket(DatagramPacket packet, String sharedSecret) throws IOException, RadiusException {
        ByteArrayInputStream in = new ByteArrayInputStream(packet.getData());
        //decodeRequestPacket - Reads a Radius request packet from the given input stream and creates an appropriate RadiusPacket descendant object.
        return RadiusPacket.decodeRequestPacket(in, sharedSecret);
    }


    @Override
    protected RadiusPacket handlePacket(InetSocketAddress localAddress, InetSocketAddress remoteAddress, RadiusPacket request, String sharedSecret) throws RadiusException, IOException {
        RadiusPacket response = null;
        if (!isPacketDuplicate(request, remoteAddress)) {
            if (localAddress.getPort() == getAuthPort()) {
                // handle packets on auth port
                if (request instanceof AccessRequest)
                    response = accessRequestReceived((AccessRequest) request, remoteAddress);
                else {
                    logger.error("unknown Radius packet type: " + request.getPacketType());
                }
            } else if (localAddress.getPort() == this.getAcctPort()) {
                if (request instanceof AccountingRequest) {
                    response = this.accountingRequestReceived((AccountingRequest) request, remoteAddress);
                } else {
                    logger.error("unknown Radius packet type: " + request.getPacketType());
                }
            }
        } else {
            logger.info("ignore duplicate packet");
        }

        return response;
    }

    //Constructs an answer for an Access-Request packet.
    @Override
    public RadiusPacket accessRequestReceived(AccessRequest accessRequest, InetSocketAddress client) throws RadiusException {
        //if validated find user in by username in getUSerPassword. verification of password. or allowed port.
        //return Access-Accept response(RadiusPacket). Configuration values(Login Model.User, protocol host maybe)
        //return null;//Access-reject response. May include text that can be displayed to the user.
        String plaintext = getUserPassword(accessRequest.getUserName());
        int type = RadiusPacket.ACCESS_REJECT;
        //verifyPassword() Verifies that the passed plain-text password matches the password (hash) send with this Access-Request packet.
        if (plaintext != null && accessRequest.verifyPassword(plaintext))
            type = RadiusPacket.ACCESS_ACCEPT;

        RadiusPacket answer = new RadiusPacket(type, accessRequest.getPacketIdentifier());

        return answer;
    }

    public void start(boolean listenA) {
        addUsers();
        if (listenA) {
            //start new thread that opens datagramSocket for UDP connection
            new Thread() {
                public void run() {
                    setName("Radius Auth Listener");
                    try {
                        logger.info("starting RadiusAuthListener on port " + getAuthPort());
                        //listenAuth() runs method listen(getAuthSocket()). Starts socket, listens on port and receives datagram.
                        listenAuth();
                    } catch (Exception e) {
                        e.printStackTrace();
                    } finally {
                        if (authSocket != null && (!authSocket.isClosed())) {
                            authSocket.close();
                            logger.debug("auth socket closed");
                        }
                    }
                }
            }.start();
        }
    }
    public void stop() {
        logger.info("stopping Radius server");
        closing = true;
        if (authSocket != null)
            authSocket.close();
    }
    public void addUsers(){
        User user = new User("frans1", "fran123!");
        User user2 = new User("frans2", "fran123!");
        userStorage = new UserStorage();
        userStorage.saveUser(user);
        userStorage.saveUser(user2);
    }
}
