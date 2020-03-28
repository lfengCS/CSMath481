package edu.capital.eave.seminar_sp19.chat_client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import edu.capital.eave.seminar_sp19.chat_server.ServerPackets;
import edu.capital.eave.seminar_sp19.chat_server.db.SimpleChatDatabase;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.input.KeyCode;
import javafx.stage.WindowEvent;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Controller {

    // Our private key information which will be hardcoded for now
    private PrivateKey privateKey = null;

    private Socket socket;

    @FXML
    private TextField searchTextField;

    @FXML
    private Button addConversationButton;

    @FXML
    private ListView<String> conversationListView;

    @FXML
    private TextArea messageDisplayTextArea;

    @FXML
    private TextField messageTextField;

    @FXML
    public void initialize() {

        // User information is hardcoded for now. Ideally login would connect to the database
        // and check the user's login credentials. Also, the private key would be stored in
        // an aes encrypted file on the users machine.
        String ourUser;
        String recipient;
        BigInteger privExp;
        BigInteger prime1;
        BigInteger prime2;

        if(Constants.USE_USER_ETHAN) {
            ourUser = "ethan";
            recipient = "chris";
            privExp = new BigInteger("256727176141294800617927798643927916265822923447233431925334500572235866948033280619400113142162169489351013681524671988119616527114527807386250985672748764463800935051605942912466043524918974491556408190884923358283043146203003031726960096600135066274452482811697545804575554131509596641233224741549419765199619335327136196731846098335701465018825124082979491670489761407068816670202088816649213534242514088810969487737592024022673870951790167549016947437586504639390420914300340795063236808811422680454822002243851345915911118282763037162330399186208368712388874571668944263755299408763244305560075492954820871290192443794227103567051577498950558189888520228607273945052626492738882380166282488183695645474226532833571341762445747871545285292519108308061231904888931068579335983826051294432621607880978908417949167055348569779328039703166841272338410182525293543008514981078097179814614683422027007148480887911541029674864538292512693380108853415393127511366616717524325364674363915926280749292712299025743444692839982829085778778431432062669703277911310068012436625033923241687940563656780467926830555447998091240704325548520671804020585267132166522511516308463411905969165862123252849169611186487090331731287323417278152605336305");
            prime1 = new BigInteger("18763990315043787462095888931804686229700626009575567200889724822030445108323163720819616107592568708213546692334044313070346135494773641725576837032554904116331870327527423249523209254260349595421216743959056117659299730327869932983713255216125840698431074810652519154258665345304181917153729454249777118254719120885079040002472525980229637728673525061399720119608008538632014715256890111976186346099702898104555178546032617092183066207320442207192033968901266177221810752153665679962094249033799868135465855287237642579114728191078863501538211362209435979782281806761440195347850728049780631273060417389551737563527");
            prime2 = new BigInteger("27261071353954046727983537398185415773340150100286023737084855146894119995336239065265487697404565568764073007766364603498552530045970993240845714056793326791977141997219500995199217263367580378049605416273148187305082695033517154006743469480631523730906534567932615988114098721393680454061592660735470737735902094676840565718552859116455425127390437052454247802936149411480621345060512349995906090552604512465068096919372025930595189630560741652097825736978749857786840557281915057269199782486229844981137543728888742386002810008059254220234486629874882357473135759220499533151864363440832271152709674819324814851703");
        } else {
            ourUser = "chris";
            recipient = "ethan";
            privExp = new BigInteger("175905622099303773531780106910296119717227336307397323743783944422334187213277175307273702426805294787620188713077354372206088546977407231045369629591818655336449411418552131576347224623768912142061902117461009910869904861044306206893325286005331939023930643274974080755205767354241850103001565788475694626663007891326991889690269623907569900576631659802255990899115071248442423072064182628500486600705955384693194882233603163445522566979307598469913337011182995575829932681737248195723623259886977443422096013643725666403066107539557800865226213008415101101406526450345214849686621985530107150207202123614249876408431689107795197170768858563235604470637174667418209543598927800492267420160078193793717221610465822271946025809629837340481252802425129751910988923018323853744777765331561342951710413053988320167846104534166397160683533288164520128732830851430552683989538798509594855043575898467566817084637864935137996792538828317429179392903247851643072698684592320199933267318702351871720616821661402284988638070117101213879070602229611684576571200393652849177434574139693695567153713383627401211478470242559857402216551478933298453003207980311727157755263113819259970937917544952974959341067326297342755576219504357500228971227121");
            prime1 = new BigInteger("27644755869255333148550553732642123909565492977974196099536586169922265142783028368047966958642541223141828139785895535995605592827079497929655843842851966940228764742484026988161652810601715765218260714125561534640242534461768849733331994989003159378794215855680448450149059627940410692770472459193831874260759169614261078474031227577605644893539768775124316163042497790745759158469595378270365251117729137258982807947823982616589843370515569373529261196466722916826337679756323266565370566242556456908983003465156044452686641766111630318138023749650691966312171818097152786076578811215239697495761045163521714166119");
            prime2 = new BigInteger("18547267763289862094100482437169464052048008597598544260133858893323253048375147666448393812895133508983982630616386588360652296463789439108387942229345333230574324998754854728784924879104870627988491462579430101448741509246127425101270812933440662343405812342162309582078992697228653470095075413788973177594427785213282956871892088789807168761337655121154703985304558641826664261220418867002433054079637249093415558481745005304090767500820129841729099343053878350688726396853518667280067523046688687452822455651654678937278167553374799954663517167530613397966310748529566811698689231909263366273477678901729410376099");
        }


        BigInteger modulus = prime1.multiply(prime2);

        // Create our PrivateKey instance that we will use to decrypt incoming messages
        try {
            RSAPrivateKeySpec spec = new RSAPrivateKeySpec(modulus, privExp);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(spec);
        } catch(Exception e ) {
            e.printStackTrace();
        }

        ObservableList conversations = FXCollections.observableArrayList("Ethan", "Chris");
        FilteredList<String> filteredConversations = new FilteredList<>(conversations, s -> true);
        conversationListView.setItems(filteredConversations);
        // TODO: When a proper account system is added, this list needs to be populated with
        // TODO: our friends list and clicking each user needs to open a direct chat with that user


        // Setup the username search functionality
        searchTextField.setOnKeyReleased(event -> {
            if (event.getCode() == KeyCode.ENTER) {
                String text = searchTextField.getText();
                filteredConversations.setPredicate(item -> {
                    if (item.contains(text)) {
                        return true;
                    }
                    return false;
                });
                conversationListView.setItems(filteredConversations);
            }
        });


        try {

            // Get our server ip address
            InetAddress ip = InetAddress.getByName(Constants.SERVER_IP);

            // Establish the connection to the server
            socket = new Socket(ip, Constants.SERVER_PORT);

            // Get our input and output streams for writing packets
            DataInputStream dis = new DataInputStream(socket.getInputStream());
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());

            // Send login packet
            dos.writeInt(0);
            dos.writeUTF(ourUser);

            // Setup logout on close
            Main.mainStage.setOnCloseRequest(new EventHandler<WindowEvent>() {

                @Override
                public void handle(WindowEvent arg0) {
                    System.out.println("Logging out...");
                    try {
                        dos.writeInt(255);//logout packet
                        socket.close();
                        Platform.exit();
                        System.exit(0);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                }

            });


            // Setup an on key release event handler for the message textfield
            messageTextField.setOnKeyReleased(event -> {

                // When the user presses and releases the enter key the
                // text in the textfield will be encrypted and sent to the
                // other user
                if (event.getCode() == KeyCode.ENTER) {
                    String message = messageTextField.getText();
                    messageTextField.clear();
                    System.out.println("Sending message: " + message);

                    try {

                        // Generate a 128bit SecretKey for encrypting the message
                        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                        keyGen.init(128);
                        SecretKey secretKey = keyGen.generateKey();
                        System.out.println("Generated secret key: " + Arrays.toString(secretKey.getEncoded()));


                        // Create the AES cipher
                        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

                        // Generate a random initialization vector
                        SecureRandom secRand = new SecureRandom();
                        byte[] iv = new byte[cipher.getBlockSize()];
                        secRand.nextBytes(iv);
                        IvParameterSpec ivParams = new IvParameterSpec(iv);

                        // Initialize the cipher for encrypting with the secret key and
                        // initialization vector we generated
                        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);

                        // Perform the AES encryption of the message
                        byte[] cipherText = cipher.doFinal(message.getBytes());


                        // Encrypting the AES secret key with RSA
                        // Initialize the cipher with the user's public key
                        //ECB is for backwards compatibility reasons and in actuality does nothing
                        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                        BigInteger recipientPubMod = SimpleChatDatabase.getPublicKey(recipient);

                        // If we didn't find a public key in the database...
                        if(recipientPubMod == null) {
                            System.err.println("No public key found!");
                            return;
                        }

                        // We have decided to use a constant public exponent for all users
                        BigInteger recipientPubExp = Constants.PUBLIC_EXPONENT;

                        // Convert our BigIntegers into a PublicKey and initialize our cipher for encryption
                        RSAPublicKeySpec spec = new RSAPublicKeySpec(recipientPubMod, recipientPubExp);
                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                        PublicKey publicKey = keyFactory.generatePublic(spec);
                        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);

                        // Perform the RSA encryption of the secret key
                        byte[] key = rsaCipher.doFinal(secretKey.getEncoded());

                        System.out.println("Sending RSA encrypted secret key: " + Arrays.toString(key));
                        System.out.println("Sending AES encrypted ciphertext: " + Arrays.toString(cipherText) + "\n");

                        // Now we need to send the server our cipher text, IV, and RSA encrypted secret key to decrypt the ciphertext
                        dos.writeInt(ServerPackets.SEND_MESSAGE);
                        dos.writeUTF(recipient);
                        dos.writeInt(iv.length);// Send the lengths first
                        dos.writeInt(cipherText.length);
                        dos.writeInt(key.length);
                        dos.write(iv);
                        dos.write(cipherText);
                        dos.write(key);
                    } catch(Exception e) {
                        e.printStackTrace();
                    }

                    // Add the message to our own chat window
                    messageDisplayTextArea.appendText(ourUser + ": " + message + "\n");

                }
            });

            // Create a new thread for reading in packets from the server
            Thread readPacketLoop = new Thread(new Runnable()
            {
                @Override
                public void run() {

                    while (true) {
                        try {

                            if(!socket.isClosed() && dis.available() > 0) {
                                int packetId = dis.readInt();

                                if(packetId == ClientPackets.SEND_ENC_USER_MESSAGE) {

                                    // Read in the message data
                                    String from = dis.readUTF();
                                    int ivLength = dis.readInt();
                                    int cipherTextLength = dis.readInt();
                                    int encryptedSecretKeyLength = dis.readInt();
                                    byte[] iv = new byte[ivLength];
                                    byte[] cipherText = new byte[cipherTextLength];
                                    byte[] encSecretKey = new byte[encryptedSecretKeyLength];
                                    byte[] plainTextMessage = null;
                                    dis.read(iv);
                                    dis.read(cipherText);
                                    dis.read(encSecretKey);
                                    System.out.println("Received RSA encrypted secret key: " + Arrays.toString(encSecretKey));
                                    System.out.println("Received AES encrypted ciphertext: " + Arrays.toString(cipherText));

                                    // Begin message decryption
                                    SecretKey key = null;
                                    Cipher cipher = null;

                                    try {

                                        // Initialize the RSA cipher for decrypting our secretkey
                                        cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                                        cipher.init(Cipher.DECRYPT_MODE, privateKey);

                                        // Decrypt our secret key needed for decrypting the AES ciphertext
                                        key = new SecretKeySpec(cipher.doFinal(encSecretKey),"AES");
                                        System.out.println("Decrypted secret key: " + Arrays.toString(key.getEncoded()));

                                        // Initialize the cipher for decrypting our AES ciphertext
                                        IvParameterSpec ivParams = new IvParameterSpec(iv);
                                        cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                                        cipher.init(Cipher.DECRYPT_MODE, key, ivParams);

                                        // Decrypt the ciphertext to get our plaintext
                                        plainTextMessage = cipher.doFinal(cipherText);
                                    } catch(Exception e) {
                                        e.printStackTrace();
                                    }

                                    // Add the message to our chat/display error message if decryption failed
                                    if(plainTextMessage != null) {
                                        String message = new String(plainTextMessage);
                                        System.out.println("Decrypted message: " + message + "\n");
                                        messageDisplayTextArea.appendText(from + ": " + message + "\n");
                                    } else {
                                        messageDisplayTextArea.appendText("Unable to properly decrypt message from " + from + ".\n");
                                    }
                                } else if(packetId == ClientPackets.FATAL_ERROR_MESSAGE) {
                                    String message = dis.readUTF();
                                    System.err.println(message);
                                    socket.close();
                                    System.exit(0);


                                }

                            }
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }

            });

            readPacketLoop.start();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}
