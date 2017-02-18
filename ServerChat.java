package ChatApp;

/**
 * Imports needed for application
 */
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.io.FileUtils;
import org.apache.commons.codec.binary.Base64;


/**
 * Imports needed for GUI
 */
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

/**
 * Application to conduct secure transfer of information between 2 entities The
 * Chat Application GUI Activity
 */
public class ServerChat extends JFrame implements ActionListener {

    // Declaration of member variables
    static Socket sock;//creating a socket
    static ServerSocket server;//setting up a socket server
    static Random rndm = new Random();//used to find a random prime number
    private static String localIP = "127.0.0.1"; // localhost
    private static boolean nextFileFlag = false;//used to identify whether or not a file is being sent
    private static boolean nextKeyGenFlag = false;//used to identify whether or not a mutual key is being sent
    private static boolean keyGenFlag = false;//used to show whether or not a mutual key is in use
    private static int encryptType = 0;//used to select encryption algorithm 
    private static int decryptType = 0;//used to select decryption algorithm 
    private static int keyGenStage = 0;//used to identify the stage of mutual key generation taking place
    private static int fileSize = 0;//used to initialise the fileSize variable
    private static long myNonce = 0;//nonce used in hash function
    private static long otherNonce = 0;//used to store a received nonce
    private static long completeNonce = 0;//used to combine received nonce with local nonce
    private static String fileName = null;//used to initialise the fileName variable


    // DEFINED STRINGS
    final static String MSGSTART = "%MsgSta%";//used to identify the start of a message transmission
    final static String MSGEND = "%MsgEnd%";//used to identify the end of a message transmission
    final static String FILETRANS = "%FILETS%";//used to identify the start of a file transmission
    final static String FILETRANE = "%FILETE%";//used to identify the end of a file transmission
    final static String AESKST = "%AESKSt%";//used to identify the start of a AES transmission
    final static String AESKED = "%AESKEd%";//used to identify the end of a AES transmission
    final static String DHKEYST = "%DHKySt%";//used to identify the start of a Diffe Hellman transmission
    final static String DHKEYEND = "%DHKyEd$";//used to identify the end of a Diffe Hellman transmission
    final static String RSAKEYST = "%RSAPKS%";//used to identify the start of a RSA transmission
    final static String RSAKEYEND = "%RSAPKE%";//used to identify the end of a RSA transmission
    final private static String fileLocation = "C:\\Users\\Hugh\\Pictures";//initial directory searched
    final private static String fileOutLocation = "C:\\Users\\Hugh\\Downloads\\";//location of output file
    final private static String userID = "Server"; // other userID

    // DEFINED INTS
    final static int PORT_NO = 50001;//port number
    final static int RSA_PUB_KEY = 5341;//used to switch between message types
    final static int RSA_KEY_SIZE = 1024;//size of RSA key
    final static int AES_KEY = 6565;//used to switch between message types
    final static int AES_KEY_SIZE = 128;//size of AES key
    final static int DH_KEY = 4563;//used to switch between message types
    final static int IMG_FIL = 2545;//used to switch between message types
    final static int TXT_MSG = 1342;//used to switch between message types
    final static int MSG_ERR = 345;//used to switch between outcome message types
    final static int SENT = 96;//used to switch between outcome message types
    final static int RECEIVED = 69;//used to switch between outcome message types
    final static int NOTIFIC = 456;//used to switch between outcome message types
    final static int ID_SIZE = 8;//used to identify the size of ID's in defined strings

    // Two 512 bit primes
    final static private BigInteger PRIME_P = new BigInteger("45847171455399874841532283724392696345237334210234926264171552308945326342451265418785837711773788191993231138584899306298332165488486807876261906041111953");
    final static private BigInteger PRIME_Q = new BigInteger("31983610456021160748866632775297796669857872353217322498190680353757443240103757420849209410055387034931807318397291936497508757944522736309273423325368919");
    final static BigInteger PRIV_KEY = BigInteger.probablePrime(256, rndm);//Private key

    // Declare RSA/AES Key variables
    static KeyPairGenerator kpg;//used to initialise an instance of a RSA key pair generator
    static Key publicKey;//sent to client to allow for RSA encoding
    static Key privateKey;//used by RSA to decrypt messages sent by public key
    static Key otherPublicKey;//used to encode messages sent to client with its public key
    static BigInteger clientDHKey;//initialise the client diffe hellman key
    static BigInteger serverDHKey;//initialise the server diffe hellman key
    static SecretKey sharedDHKey;//used to generate inital diffe hellman key for initial RSA exchange
    static SecretKey sharedKey;//used to store mutually generated AES Key
    static byte[] iv = new byte[16];//AES initialisation vector
    static SecureRandom secRand = new SecureRandom();//used to gernerate random  AES initialisation vector
    static IvParameterSpec ivParameterSpec;//used to specifiy initialisation vector

    // Declaration of GUI variables
    static JFrame chatFrame;
    static JPanel chatPanel;
    static JPanel infoBar;
    static JLabel encTypeLabel;
    static JTextField newMsg;
    static JTextArea messageDisplay;
    static JScrollPane scrollPane;
    static JButton sendButton;
    static JButton keyGenButton;
    static JButton browseButton;

    /**
     * Default Constructor for Client Chat Form
     *
     * @throws UnknownHostException
     * @throws IOException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     */
    public ServerChat() throws UnknownHostException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        // Initialisation of Member Variable
        chatFrame = new JFrame();
        chatPanel = new JPanel();
        newMsg = new JTextField();
        messageDisplay = new JTextArea();
        scrollPane = new JScrollPane(messageDisplay); 
        sendButton = new JButton("Send");
        infoBar = new JPanel();
        encTypeLabel = new JLabel("");
        keyGenButton = new JButton("Gen Session Key");
        browseButton = new JButton("Browse");

        // Initialisation of GUI variables
        chatFrame.setSize(500, 500);
        chatFrame.setVisible(true);
        chatFrame.setDefaultCloseOperation(EXIT_ON_CLOSE);
        chatPanel.setLayout(null);
        chatFrame.add(chatPanel);
        infoBar.setBounds(20, 10, 450, 40);
        encTypeLabel.setBounds(20, 0, 200, 20);
        encTypeLabel.setAlignmentX(LEFT_ALIGNMENT);
        keyGenButton.setBounds(350, 0, 100, 20);
        keyGenButton.setAlignmentX(RIGHT_ALIGNMENT);
        infoBar.add(encTypeLabel);
        infoBar.add(keyGenButton);
        chatPanel.add(infoBar);
        scrollPane.setBounds(20, 60, 450, 320);
        chatPanel.add(scrollPane);
        newMsg.setBounds(20, 400, 340, 30);
        chatPanel.add(newMsg);
        sendButton.setBounds(375, 390, 95, 30);
        chatPanel.add(sendButton);
        browseButton.setBounds(375, 425, 95, 30);
        chatPanel.add(browseButton);
        chatFrame.setTitle("Chat Server");
        /**
         * ###############* END GUI PAINT *################
         */

        /**
         * ###############* ACTIONLISTENERS *################
         */
        sendButton.addActionListener((ActionEvent e) -> {//action listener send button
            String message = newMsg.getText();//used to take in message
            if ((e.getSource() == sendButton) && (!"".equals(message))) {//if the send button is hit and the message isn't blank
                try {
                    sendMessage(message, TXT_MSG);
                } catch (UnsupportedEncodingException ex) {
                    Logger.getLogger(ServerChat.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
        
        newMsg.addActionListener((ActionEvent e) -> {//action listener jTextField
            String message = newMsg.getText();//used to take in message
            if ((!"".equals(message))) {//if enter is hit and the message is blank
                try {
                    sendMessage(message, TXT_MSG);
                } catch (UnsupportedEncodingException ex) {
                    Logger.getLogger(ServerChat.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
      
        keyGenButton.addActionListener((ActionEvent e) -> {//action listener Generate key button
            String passPhrase = JOptionPane.showInputDialog(null, "Please Enter an eight character password or shorter!");//text dialoge box requesting password
            try {
                mutualGenKey(passPhrase);
            } catch (UnsupportedEncodingException | NoSuchAlgorithmException ex) {
                Logger.getLogger(ServerChat.class.getName()).log(Level.SEVERE, null, ex);
            }
            nextKeyGenFlag = true;//set the flag to true as there will be a mutually generated key
        });
        
        browseButton.addActionListener((ActionEvent e) -> {//action listener browse for file key button
            JFileChooser fc = new JFileChooser(fileLocation);//create a new file chooser starting at initial location
            fc.showOpenDialog(null);
            File myFile = fc.getSelectedFile();//get the selected file
            try {
                String fileNameSize = myFile.getName() + "::" + myFile.length();
                sendMessage(fileNameSize, IMG_FIL);
                displayMessage(myFile.getName(), SENT);
                sendFile(myFile);
            } catch (Exception e1) {
                displayMessage(e1.toString(), NOTIFIC);
            }
        });
        
        connect();
        
        while (true) {
            pollForData();//constantly poll for incoming data
        }
    }

    /**
     * Main method of Class ServerChat
     */
    public static void main(String[] args) throws UnknownHostException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        ServerChat chatForm = new ServerChat();//set up a new server chat
    }

    /**
     * Method to open Server Socket and allow connections
     */
    private static void connect() throws IOException {     
        server = new ServerSocket(50001, 1, InetAddress.getByName(localIP));//set up a new server socket
        messageDisplay.setText("\tWaiting for Client");
        sock = server.accept();//accept connection to socket
        displayMessage("Client Found", NOTIFIC);
        BigInteger intA = generateMyDHKeyPart(PRIME_P, PRIME_Q, PRIV_KEY);//generate a diffe hellman key part
        sendMessage(intA.toString(), DH_KEY); //send diffe hellman key
    }

    /**
     * Method to generate Diffie-Hellman key for secure key exchange Calculated
     * using key = q^a mod p
     * p 512 bit prime number not secret
     * q 511 bit prime number not secret
     * returns a key used to mutually generate a shared secret key for RSA exchange
     */
    private static BigInteger generateMyDHKeyPart(BigInteger p, BigInteger q, BigInteger a) {
        BigInteger key = q.modPow(a, p);
        return key;
    }

    /**
     * Method to generate a shared Diffie-Hellman Key for initial RSA key
     * exchange
     */
    private static void generateSharedDHKey(BigInteger clientDH, BigInteger privateKey, BigInteger p) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        BigInteger k = clientDH.modPow(privateKey, p);//generate a big int to be hashed
        byte[] hashedKey = hashFunction(k.toString(), "MD5");//hash the big int
        sharedDHKey = new SecretKeySpec(hashedKey, 0, hashedKey.length, "AES");//shared key used for initial exchange
    }

    /**
     * Method to generate RSA public and private keys
     */
    private static void generateRSAKeys() throws NoSuchAlgorithmException {
        kpg = KeyPairGenerator.getInstance("RSA");//use RSA
        kpg.initialize(2048);//initialise key pair generator
        KeyPair kp = kpg.genKeyPair();//generate a a key pair public and private key
        publicKey = kp.getPublic();//get RSA Public key
        privateKey = kp.getPrivate();//get RSA Private key
    }

    /**
     * Method to invoke the mutual AES key generation
     */
    private static void mutualGenKey(String msg) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        /*variables used to encrypt and decrypt text*/
        byte[] hashPass = null;
        byte[] digSignBytes;
        byte[] nonceBytes;
        byte[] responseBytes;
        byte[] signCipher64;
        byte[] nonceCipher64;
        byte[] responseCipher64;
        byte[] authSign;
        byte[] authSign64;
        byte[] nonHash;
        byte[] nonceDec;
        String signCipherText;
        String nonceCipherText;
        String responseCipherText;
        String fullMsg;
        String fullNonStr;
        String str2int = "";
        String[] parts;
        long secLong = secRand.nextInt();
        
        switch (keyGenStage) {
            case 0:
                if (msg.length() > 8) {
                    displayMessage("Invalid pass phrase length, must be 8 characters or less", NOTIFIC);
                    break;
                }
                for (int i = 0; i < msg.length(); i++) {
                    str2int = str2int + Character.getNumericValue(msg.charAt(i));//turn characters into numeric values
                }
                myNonce = secLong + Long.parseLong(str2int);//create a nonce
                try {
                    hashPass = hashFunction(Long.toString(myNonce), "SHA-256");//create a hash function using SHA
                } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
                    Logger.getLogger(ServerChat.class.getName()).log(Level.SEVERE, null, ex);
                }
                setEncryptionType(3); // setup digSign encryption
                digSignBytes = encrypt(hashPass);//encrypt the hash
                signCipher64 = Base64.encodeBase64(digSignBytes);
                signCipherText = new String(signCipher64);
                setEncryptionType(1); // set up RSA encryption
                nonceBytes = encrypt(Long.toString(myNonce).getBytes());//encrpyt the nonce
                nonceCipher64 = Base64.encodeBase64(nonceBytes);
                nonceCipherText = new String(nonceCipher64);
                fullMsg = nonceCipherText + "::" + signCipherText;//create the full message using the nonce and hash
                setEncryptionType(0);
                sendMessage(fullMsg, AES_KEY);// send the message
                keyGenStage += 1;//move to the next stage
                nextKeyGenFlag = true;//set the key generated flag to true
                break;
           
            case 1:
                msg = msg.substring(ID_SIZE, msg.length()-ID_SIZE);
                parts = msg.split("::");//split the recieved message into hash and nonce
                setDecryptionType(3);
                authSign64 = Base64.decodeBase64(parts[2].getBytes());//decrpyt the hash
                authSign = decrypt(authSign64);//store hash in authsign
                setDecryptionType(1);
                byte[] nonceDec2 = decrypt(Base64.decodeBase64(parts[1].getBytes()));//decrypt the nonce
                String nonceDecStr2 = new String(nonceDec2, "UTF-8");//get the nonce string
                byte[] hash2 = hashFunction(nonceDecStr2, "SHA-256");//generate a hash using the nonce
                
                if (Arrays.equals(authSign, hash2)) {//compare recieved hash to generated
                    otherNonce = Long.parseLong(nonceDecStr2);
                    displayMessage("Nonce successfully recieved", NOTIFIC);
                    completeNonce = myNonce + otherNonce;//create the complete nonce using both recieved and sent nonces
                    fullNonStr = Long.toString(completeNonce);
                    nonHash = hashFunction(fullNonStr, "MD5");//create a new AES secret key
                    sharedKey = new SecretKeySpec(nonHash, 0, nonHash.length, "AES");
                    keyGenFlag = true;//set key gen flag ture
                    nextKeyGenFlag = false;//set next key gen to false      
                    setEncryptionType(2);
                    responseBytes = encrypt(nonceDecStr2.getBytes());//encrypt nonce with AES key
                    responseCipher64 = Base64.encodeBase64(responseBytes);
                    responseCipherText = new String(responseCipher64);                  
                    setEncryptionType(0);
                    sendMessage(responseCipherText, AES_KEY);//send back nonce to identify encrypted with AES key
                    displayMessage(sharedKey.toString(), NOTIFIC);
                } else {
                    sendMessage("Your Nonce was NOT decrypted successfully", TXT_MSG);
                    displayMessage("The other Nonce was NOT decrypted successfully", NOTIFIC);
                }    
                setDecryptionType(2);
                if (Arrays.equals(decrypt(Base64.decodeBase64(parts[0].getBytes())), Long.toString(myNonce).getBytes())) {
                    displayMessage("Challenge Response received.", NOTIFIC);
                    nextKeyGenFlag = false;
                } else {
                    displayMessage("Challenge Response Not Recieved, Process terminated.", NOTIFIC);
                    nextKeyGenFlag = false;
                }
                break;
                
            case 2:
                String passPhrase = JOptionPane.showInputDialog(null, "Please Enter a password/phrase 8 chars or shorter.");
                if (passPhrase.length() > 8) {
                    displayMessage("Invalid pass phrase length, must be 8 characters or less", NOTIFIC);
                    break;
                }
                for (int i = 0; i < passPhrase.length(); i++) {
                    str2int = str2int + Character.getNumericValue(passPhrase.charAt(i));//turn characters into numeric values
                }
                myNonce = secLong + Long.parseLong(str2int);
                try {
                    hashPass = hashFunction(Long.toString(myNonce), "SHA-256");//create a hash function using SHA
                } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
                    Logger.getLogger(ServerChat.class.getName()).log(Level.SEVERE, null, ex);
                }
                
                parts = msg.split("::");//split the recieved message into hash and nonce
                setDecryptionType(3);
                authSign64 = Base64.decodeBase64(parts[1].getBytes());//decrpyt the hash
                authSign = decrypt(authSign64);//store hash in authsign
                setDecryptionType(1);
                nonceDec = decrypt(Base64.decodeBase64(parts[0].getBytes()));//decrypt the nonce
                String nonceDecStr = new String(nonceDec, "UTF-8");//get the nonce string
                byte[] hash = hashFunction(nonceDecStr, "SHA-256");//generate a hash using the nonce
                if (Arrays.equals(authSign, hash)) {//compare recieved hash to generated
                    otherNonce = Long.parseLong(nonceDecStr);
                    displayMessage("Nonce successfully recieved", NOTIFIC);
                    completeNonce = myNonce + otherNonce;//create the complete nonce using both recieved and sent nonces
                    fullNonStr = Long.toString(completeNonce);
                    nonHash = hashFunction(fullNonStr, "MD5");//create a new AES secret key
                    sharedKey = new SecretKeySpec(nonHash, 0, nonHash.length, "AES");
                    keyGenFlag = true;//set key gen flag ture
                    displayMessage(sharedKey.toString(), NOTIFIC);
                    
                } else {
                    sendMessage("Your Nonce was NOT decrypted successfully", TXT_MSG);
                    displayMessage("The other Nonce was NOT decrypted successfully", NOTIFIC);
                }
                
                setEncryptionType(3); // setup digSign encryption
                digSignBytes = encrypt(hashPass);//set up a hash
                signCipher64 = Base64.encodeBase64(digSignBytes);
                signCipherText = new String(signCipher64);
                setEncryptionType(1); // set up RSA encryption
                nonceBytes = encrypt(Long.toString(myNonce).getBytes());//create a new nonce
                nonceCipher64 = Base64.encodeBase64(nonceBytes);
                nonceCipherText = new String(nonceCipher64);
                setEncryptionType(2);
                responseBytes = encrypt(nonceDecStr.getBytes());//rencrypt the old nonce to show that you could decrpyt it 
                responseCipher64 = Base64.encodeBase64(responseBytes);
                responseCipherText = new String(responseCipher64);
                fullMsg = responseCipherText + "::" + nonceCipherText + "::" + signCipherText;
                setEncryptionType(0);
                sendMessage(fullMsg, AES_KEY);//send back origional nonce, new nonce, and hash
                keyGenStage += 1;//nect stage
                break;                
                
            case 3:               
                msg = msg.substring(ID_SIZE, msg.length()-ID_SIZE);
                setDecryptionType(2);
                authSign64 = Base64.decodeBase64(msg.getBytes());
                authSign = decrypt(authSign64);//check that sender was a able to decrypt nonce
                if(Arrays.equals(authSign, Long.toString(myNonce).getBytes())){
                    displayMessage("Challenge Response received.",NOTIFIC);
                    nextKeyGenFlag = false;
                }else{
                    displayMessage("Challenge Response Not Recieved, Process terminated.",NOTIFIC);
                    nextKeyGenFlag = false;
                }
            default:
                break;
        }
    }

    /**
     * Method to transfer public key to client/server
     */
    private static void sendPubKey() {
        setEncryptionType(2); // use DH key for encryption
        try {
            generateRSAKeys();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ServerChat.class.getName()).log(Level.SEVERE, null, ex);
        }
        byte[] pubKeyByte = publicKey.getEncoded();//encyrt the key
        String encodedKey = java.util.Base64.getEncoder().encodeToString(pubKeyByte);//encrypt the key base 64
        displayMessage("Public Key Sent", NOTIFIC);
        try {
            sendMessage(encodedKey, RSA_PUB_KEY);//send the encoded key
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(ServerChat.class.getName()).log(Level.SEVERE, null, ex);
        }
        setEncryptionType(0); // set encryption back to none
    }

    /**
     * Method to send the text in the JTextField to the Client/Server
     *
     * 2040 - Message 2141 - RSA Public Key 2343 - AES Key
     */
    private static void sendMessage(String input, int messageType) throws UnsupportedEncodingException {
        String strSent;
        switch (messageType) {
            case TXT_MSG:
                displayMessage(input, SENT);
                strSent = MSGSTART + input + MSGEND;//add the header and footer to the message
                break;
            case RSA_PUB_KEY:
                strSent = RSAKEYST + input + RSAKEYEND;//add the header and footer to the message
                break;
            case DH_KEY:
                strSent = DHKEYST + input + DHKEYEND;//add the header and footer to the message
                break;
            case IMG_FIL:
                strSent = FILETRANS + input + FILETRANE;//add the header and footer to the message
                break;
            case AES_KEY:
                strSent = AESKST + input + AESKED;//add the header and footer to the message
                break;
            default:
                strSent = "Error in sending";
                break;
        }
        byte[] plainByte = strSent.getBytes();
        byte[] cipherBytes = encrypt(plainByte);// encrypt the byte array
        byte[] cipher64 = Base64.encodeBase64(cipherBytes);//encrypt the array in base 64
        String cipherText = new String(cipher64);//used to encrypt the string
        try {
            DataOutputStream dos = new DataOutputStream(sock.getOutputStream());//used the send the string on
            dos.writeUTF(Integer.toString(encryptType));
            dos.writeUTF(cipherText);
        } catch (Exception e1) {
            try {
                Thread.sleep(3000);
                System.exit(0);
            } catch (InterruptedException e2) {
            }
        }
        newMsg.setText("");
    }
    /**
     * Method to send the file chosen by the "Browse" JButton over a socket
     */
    private void sendFile(File file) throws IOException {
        
        ServerSocket servsock = new ServerSocket(13267);//set up a new socket to send a file
        try {
            Socket sock = servsock.accept();//accept the connections from the socket
            byte [] byteArray  = new byte [(int)file.length()];//set up a byte array that is the size of the file
            BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file));
            bis.read(byteArray,0,byteArray.length);
            DataOutputStream dos = new DataOutputStream(sock.getOutputStream());//set up a data output stream
            byte[] encByteArray = encrypt(byteArray);// encrypt the byte array
            byte[] encByteArray64 = Base64.encodeBase64(encByteArray);//encrypt the array in base 64
            dos.write(encByteArray64, 0, encByteArray64.length); //write bytes to output stream
            dos.flush();//flush the data output stream
            dos.close(); //close data ouput stream 
            sock.close(); // close socket
            servsock.close(); // close server socket    
        } catch (IOException io) {
            System.err.println(io);
        }
    }

    /**
     * Method to receive file from socket once nextFileFlag is set
     */
    private static void receiveFile() throws IOException {
        int bytesRead;
        int current = 0;
        try {
        	fileSize = 9022386;//receive a file of size up to 9MB
            Socket sock = new Socket(localIP, 13267);//set up a new socket to receive a file
            String outputLocation = fileOutLocation + fileName;//file output location
            byte[] mybytearray = new byte[fileSize];//set up a byte array that is the size of the file
            InputStream is = sock.getInputStream();//input stream to take in file
            FileOutputStream fos = new FileOutputStream(outputLocation);//set up a file output stream
            BufferedOutputStream bos = new BufferedOutputStream(fos);//new buffered output stream
            bytesRead = is.read(mybytearray,0,mybytearray.length);//read in the file
            current = bytesRead;
            do {
                bytesRead =
                   is.read(mybytearray, current, (mybytearray.length-current));
                if(bytesRead >= 0) current += bytesRead;
             } while(bytesRead > -1);//used to reorder the bytes
            bos.write(mybytearray, 0 , current);
            bos.flush();//flush the buffered output stream
            displayMessage("File " + fileName + " downloaded (" + current + " bytes read)", NOTIFIC);
            System.out.println(outputLocation);
            byte[] encFile = FileUtils.readFileToByteArray(new File(outputLocation));//read in the file than decrypt
            byte[] decodedValue = new Base64().decode(encFile);//decrypt the array in base 64
            byte[] decFile = decrypt(decodedValue);// decrypt the byte array
            FileUtils.writeByteArrayToFile(new File(outputLocation), decFile);//write out the decrypted file
            
            fos.flush(); // flush file output stream
            fos.close(); //close file output stream 
            sock.close(); // close the socket
            displayMessage("File Received Successfuly.", NOTIFIC);
            
        } catch (IOException io) {
            System.err.println(io);
        }
    }

    /**
     * Method to continuously poll for incoming data.
     */
    private static void pollForData() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            if (nextFileFlag == true) {//check if its a file coming in
                receiveFile();//call file being received
                nextFileFlag = false;//set file being recived to false
                fileSize = 0;//set file size back to 0
            } else {
                DataInputStream dis = new DataInputStream(sock.getInputStream());//set up a data input stream
                String stringReceived = dis.readUTF();//read in a string
                
                if (nextKeyGenFlag == true) {//check if a mutual key has been generated 
                    if (!stringReceived.equals("0")) {//if the string is not blank
                        byte[] cipherText = stringReceived.getBytes();
                        byte[] cipher64 = Base64.decodeBase64(cipherText);
                        byte[] plainBytes = decrypt(cipher64);//decrypt the recieved string
                        String plainText = new String(plainBytes, "UTF-8");
                        mutualGenKey(plainText);//enter into mutual key generator case 2
                    } else {
                        setDecryptionType(0);
                    }//else if the string is case 0, 1, 2, or the nextkeygenflag is false
                } else if (("0".equals(stringReceived) || "1".equals(stringReceived) || "2".equals(stringReceived)) && (nextFileFlag == false)) {
                    int newType = Integer.parseInt(stringReceived);
                    if (decryptType != newType) {
                        decryptType = newType;//set the new decrypt method if it isn't set
                    }
                } else {
                    byte[] cipherText = stringReceived.getBytes();
                    byte[] cipher64 = Base64.decodeBase64(cipherText);
                    byte[] plainBytes = decrypt(cipher64);
                    String plainText = new String(plainBytes, "UTF-8");
                    String formatOfString = plainText.substring(0, ID_SIZE);
                    String succesfulSend = plainText.substring((plainText.length() - ID_SIZE), plainText.length());
                    String actualString = plainText.substring(ID_SIZE, (plainText.length() - ID_SIZE));
                    switch (formatOfString) {//used to reformat the string back into readable output
                        case MSGSTART:
                            if (succesfulSend.equals(MSGEND)) {
                                displayMessage(actualString, RECEIVED);
                            } else {
                                displayMessage("Full Message Not Recieved", MSG_ERR);
                            }
                            break;
                        case RSAKEYST:
                            if (succesfulSend.equals(RSAKEYEND)) {
                                displayMessage("Public Key Received and Saved", NOTIFIC);
                                byte[] decodedKey = java.util.Base64.getDecoder().decode(actualString);//decode the string
                                otherPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decodedKey));
                                //get the client public key
                            } else {
                                displayMessage("Full Message Not Recieved", MSG_ERR);
                            }
                            break;
                        case DHKEYST:
                            if (succesfulSend.equals(DHKEYEND)) {
                                generateSharedDHKey(new BigInteger(actualString), PRIV_KEY, PRIME_P);//generate diffe hellman
                                displayMessage("Shared Key Generated and Stored.", NOTIFIC);
                                sendPubKey();//send the public key
                            } else {
                                displayMessage("DH Key Not Exchanged Properly", MSG_ERR);
                            }
                            break;
                        case FILETRANS:
                            if (succesfulSend.equals(FILETRANE)) {
                                nextFileFlag = true;
                                String[] parts = actualString.split("::");
                                fileName = parts[0]; // filename
                                fileSize = Integer.parseInt(parts[1]); // string to int
                                displayMessage("File Incoming :" + fileName, NOTIFIC);
                            } else {
                                displayMessage("Full Message Not Recieved", MSG_ERR);
                            }
                            break;
                        case AESKST:
                            if (succesfulSend.equals(AESKED)) {
                                nextKeyGenFlag = true;
                                keyGenStage += 2;//update the key generate case
                                mutualGenKey(actualString);
                            } else {
                                displayMessage("AES Key Not Exchanged Properly", MSG_ERR);
                            }
                            break;
                        default:
                            displayMessage("Incorrect Format Sent", MSG_ERR);
                            break;
                    }
                }
            }
        } catch (IOException | NoSuchAlgorithmException e1) {
            displayMessage("Disconnected from Server", MSG_ERR);
            try {
                Thread.sleep(5000);
                connect();
            } catch (InterruptedException e) {
            }
        }
    }

    /**
     * Displays message on the JTextArea
     */
    private static void displayMessage(String message, int messageDirection) {
        switch (messageDirection) {
            case SENT:
                messageDisplay.setText(messageDisplay.getText() + "\n" + "Me: " + message);
                break;
            case RECEIVED:
                messageDisplay.setText(messageDisplay.getText() + "\n" + userID + ": " + message);
                break;
            case MSG_ERR:
                messageDisplay.setText(messageDisplay.getText() + "\n" + "ERROR: " + message);
                break;
            case NOTIFIC:
                messageDisplay.setText(messageDisplay.getText() + "\nNOTIFICATION: " + message);
                break;
            default:
                break;
        }
    }

    /**
     * Default ActionListener Method (unused)
     */
    @Override
    public void actionPerformed(ActionEvent e) {
        throw new UnsupportedOperationException("Action Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    /**
     * Getter for the Server IP Address
     */
    public static String getServerIP() {
        return localIP;
    }

    /**
     * Setter/ for the Server IP Address
     */
    public static void setServerIP(String ip) throws IOException {
        localIP = ip;
    }

    /**
     * Setter for the Encryption Type
     * 
     * 0 - No Encryption 1 - RSA Encryption 2 - Session Key Encryption 3 -
     * Digitally Sign
     */
    public static void setEncryptionType(int encCode) {
        encryptType = encCode;
    }

    /**
     * Setter for the Decryption Type
     *
     * 0 - No Decryption 1 - RSA Decryption 2 - Session Key Decryption 3 -
     * Digital Signature Authentication
     */
    public static void setDecryptionType(int decCode) {
        decryptType = decCode;
    }

    /**
     * Method to encrypt a byte[] and export as a UTF8 String
     */
    private static byte[] encrypt(byte[] plain) throws UnsupportedEncodingException {
        byte[] cipherText;
        String algorithm;
        Key encKey = null;
        switch (encryptType) {//select the algorithm to be used
            case 0:
                algorithm = "None";
                break;
            case 1:
                algorithm = "RSA";
                encKey = otherPublicKey;//use the clients public key
                break;
            case 2:
                algorithm = "AES";
                if (keyGenFlag == true) {
                    displayMessage("Mutual Key in use ENC", NOTIFIC);
                    encKey = sharedKey;//use the mutually generated key
                } else {
                    encKey = sharedDHKey;//else use diffe hellman shared key
                }
                secRand.nextBytes(iv);//random initisation vector
                ivParameterSpec = new IvParameterSpec(iv);
                break;
            case 3:
                algorithm = "RSA";
                encKey = privateKey;//encrypt using private key
                break;
            default:
                algorithm = "None";
                break;
        }
        
        if (!algorithm.equals("None")) {//if an algorithm is being used
            try {
                final Cipher cipher = Cipher.getInstance(algorithm);//get the algorithm being used
                cipher.init(Cipher.ENCRYPT_MODE, encKey);
                cipherText = cipher.doFinal(plain);
                return cipherText;
                
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                displayMessage(e.toString(), NOTIFIC);
            }
        } else {
            return plain;
        }
        return ("Error Encrypting").getBytes();
    }

    /**
     * Method to decrypt an encrypted byte[] and returns a UTF8 String
     */
    private static byte[] decrypt(byte[] cipherText) throws UnsupportedEncodingException {
        byte[] plainText;
        String algorithm;
        Key decKey = null;
        switch (decryptType) {//select the algorithm being used to decrypt
            case 0:
                algorithm = "None";
                break;
            case 1:
                algorithm = "RSA";
                decKey = privateKey;//use the private key
                break;
            case 2:
                algorithm = "AES";
                if (keyGenFlag == true) {
                    displayMessage("Mutual Key in use DEC", NOTIFIC);
                    decKey = sharedKey;//use the mutually generated key
                } else {
                    decKey = sharedDHKey;//else use diffe hellman shared key
                }
                break;
            case 3:
                algorithm = "RSA";
                decKey = otherPublicKey;//decrypt using client public key
                break;
            default:
                algorithm = "None";
                break;
        }
        
        if (!algorithm.equals("None")) {//if an algorithm is being used
            try {
                final Cipher cipher = Cipher.getInstance(algorithm);//get the algorithm being used
                cipher.init(Cipher.DECRYPT_MODE, decKey);
                plainText = cipher.doFinal(cipherText);
                return plainText;
                
            } catch (NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException | InvalidKeyException e) {
                displayMessage(e.toString(), NOTIFIC);
            }
        } else {
            return cipherText;
        }
        return ("Error Decrypting").getBytes();
    }

    /**
     * Method to hash a String using a chosen Hash algorithm
     */
    private static byte[] hashFunction(String toBeHashed, String algorithm) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest hash = MessageDigest.getInstance(algorithm);//get algorithm to be used MD5 or SHA-256
        hash.update(toBeHashed.getBytes("UTF-8"));//updates the digest with specified buyte
        byte[] hashedBytes = hash.digest();//completes hashing operation preforms actions suchas padding
        
        return hashedBytes;
    }

}