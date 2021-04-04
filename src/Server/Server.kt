package Server

import utils.*
import java.awt.BorderLayout
import java.awt.Choice
import java.awt.FlowLayout
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.awt.event.ItemEvent
import java.awt.event.ItemListener
import java.io.*
import java.net.ServerSocket
import java.security.*
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import javax.swing.*
import kotlin.concurrent.thread

//La classe Server qui extend JFrame pour afficher une fenêtre
class Server(port: Int) : JFrame(), ActionListener {
    private val port: Int
    private val server: ServerSocket
    private var clientList: MutableList<ServerClient>
    private val privateRSA: PrivateKey
    private val publicRSA: PublicKey
    private val serverInputLabel: JLabel = JLabel("Envoyer un message au client n°0:")
    private val serverInput: JTextField = JTextField(15)
    private val sendButton: JButton = JButton("Envoyer")
    private val clientMessageLabel: JLabel = JLabel("Message du client:")
    private val noClientLabel: JLabel = JLabel("Il n'y a pas de client connecté")
    private val clientMessage: JLabel = JLabel("")
    private val clientSelect: Choice = Choice()
    private val actionsPanel = JPanel()

    //le constructeur
    init {
        //on initialise le server
        this.port = port
        server = ServerSocket(port)
        clientList = emptyList<ServerClient>().toMutableList()
        //on créer la pair de clés RSA
        val keyGen = KeyPairGenerator.getInstance("RSA")
        keyGen.initialize(1024)
        val keypair = keyGen.genKeyPair()
        privateRSA = keypair.private
        publicRSA = keypair.public
        //on initialise la fenêtre du serveur
        title = "Serveur"
        setBounds(500, 250, 300, 300)
        contentPane.layout = FlowLayout()
        actionsPanel.layout = BoxLayout(actionsPanel, BoxLayout.Y_AXIS)
        actionsPanel.add(clientSelect)
        actionsPanel.add(serverInputLabel)
        actionsPanel.add(serverInput)
        actionsPanel.add(sendButton)
        actionsPanel.add(clientMessageLabel)
        actionsPanel.add(clientMessage)
        add(noClientLabel)
        add(actionsPanel, BorderLayout.SOUTH)
        //Le panel principale n'est pas affiché au début
        //à la place on affiche le noClientLabel
        actionsPanel.isVisible = false
        sendButton.addActionListener(this)
        isVisible = true
        //fin de l'initialisation de la fenêtre
        //on ajoute un listener sur le clienSelect pour savoir quand le select des clients
        //change de client sélectionné
        clientSelect.addItemListener { e: ItemEvent? ->
            val selectedClient = clientList[clientSelect.selectedIndex]
            clientMessage.text = selectedClient.lastMessage
            serverInputLabel.text = "Envoyer un message au client n°${clientSelect.selectedIndex}:"
        }
    }

    //fonction permettant de démarrer le serveur
    fun start() {
        //boucle inifinit du serveur
        while (true) {
            val socket = server.accept()
            //on rejète le client si le serveur est plein
            if (clientList.size < 10) {
                val output = socket.getOutputStream()
                val input = socket.getInputStream()
                //on envoie la clé publique RSA et on récupère la clé DES du client
                val keyDES = sendPublicAndGetDES(output, input)
                //on instancie le client puis on le stock dans la liste pour le garder en mémoire
                val client = ServerClient(socket, output, input, keyDES)
                clientList.add(element = client)
                val clientId = clientList.indexOf(client)
                clientSelect.add("Client n°$clientId")
                //on affiche le panel principale et enlève le noClientLabel
                actionsPanel.isVisible = true
                noClientLabel.isVisible = false
                println("a new client is connected in the place n°${clientId}")
                //on démarre un thread pour écouter les messages du client
                thread(start = true, name = "listener to the client n°${clientId}") {
                    listener(client)
                }
            } else {
                PrintWriter(socket.getOutputStream(), true).println("the server is full you can't access it")
                socket.close()
                println("the server refused a client because it is full")
            }
        }
    }

    //envoie la clé publique au client puis récupère déchiffre et retourne sa clé DES
    private fun sendPublicAndGetDES(output: OutputStream, input: InputStream): Key {
        //On envoie la clé publique non chiffré
        output.write(publicRSA.encoded.size)
        output.write(publicRSA.encoded)
        //on récupère la clé DES
        val size = input.read()
        val bytes = input.readNBytes(size)
        //on la décrypte puis on l'instancie
        val decrypter: Cipher = Cipher.getInstance("RSA")
        decrypter.init(Cipher.DECRYPT_MODE, privateRSA)
        val result = decrypter.doFinal(bytes)
        return SecretKeySpec(result, 0, result.size, "DES")
    }

    //écoute les message d'un client passé en paramètre
    private fun listener(client: ServerClient) {
        try {
            while (true) {
                if (client.socket.isClosed) break
                //on récupère le message du client déchiffré
                val response = client.input.readDecryptedBytes(client.keyDES)
                val selectedClient = clientList[clientSelect.selectedIndex]
                //on vérifie si le client sélectionné dans l'interface est bien le client actuelle
                if (selectedClient.equals(client)) {
                    //si oui on affiche dans l'interface
                    clientMessage.text = response
                }
                //on sauvegarde le dernier message du client
                client.lastMessage = response
            }
        } catch (e: Exception) {
            //si on a une exception on ferme le client et on le supprime de la list
            val clientId = clientList.indexOf(client)
            println("the client n°$clientId will be rejected because of the error: $e")
            e.printStackTrace()
            clientList.remove(client)
            clientSelect.remove("Client n°$clientId")
            client.socket.close()
            println("deconnexion of the client n°$clientId")
            if (clientList.isEmpty()) {
                actionsPanel.isVisible = false
                noClientLabel.isVisible = true
            }
        }
    }

    //fonction qui récupère les évènements de la fenêtre du serveur
    override fun actionPerformed(e: ActionEvent?) {
        if (e!!.source == sendButton) {
            //on récupère le texte de l'input lorsque l'utilisateur clique sur le boutton "envoyer"
            val text = serverInput.text
            val selectedClient = clientList[clientSelect.selectedIndex]
            //on envoie le text chiffré au client sélectionné dans l'interface
            selectedClient.output.writeEncrypted(text, selectedClient.keyDES)
            serverInput.text = ""
        }
    }

}