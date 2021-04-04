package Client

import utils.*
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.io.*
import java.net.Socket
import java.security.Key
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import kotlin.concurrent.thread
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.swing.*

//La classe Client qui extend JFrame pour afficher une fenêtre
class Client(host: String, serverPort: Int): JFrame(), ActionListener {
    private val client: Socket
    private val output: OutputStream
    private val input: InputStream
    private var publicRSA: PublicKey? = null
    private val keyDES: Key
    private val clientInputLabel: JLabel = JLabel("Envoyer un message:")
    private val clientInput: JTextField = JTextField(15)
    private val sendButton: JButton = JButton("Envoyer")
    private val serverResponseLabel: JLabel = JLabel("Réponse  du serveur:")
    private val serverResponse: JLabel = JLabel("")

    //le constructeur
    init {
        //on instancie le client
        client = Socket(host, serverPort)
        output = client.getOutputStream()
        input = client.getInputStream()
        //on crée la clé DES
        val keyGen = KeyGenerator.getInstance("DES")
        keyGen.init(56)
        keyDES = keyGen.generateKey()
        //on envoit la clé DES au serveur
        getPublicAndSendDES()
        //on initialise le contenu de la fenêtre
        title = "Client"
        setBounds(500, 250, 300, 300)
        contentPane.layout = FlowLayout()
        val actionsPanel = JPanel()
        actionsPanel.layout = BoxLayout(actionsPanel, BoxLayout.Y_AXIS)
        actionsPanel.add(clientInputLabel)
        actionsPanel.add(clientInput)
        actionsPanel.add(sendButton)
        actionsPanel.add(serverResponseLabel)
        actionsPanel.add(serverResponse)
        add(actionsPanel, BorderLayout.SOUTH)
        sendButton.addActionListener(this)
        isVisible = true
        //fin de l'initialisation de la fenêtre
        //on démarre le thread qui va permettre d'écouter les messages du serveur
        thread(start = true, name = "client listener from the server") {
            listener()
        }
    }

    //récupère la clé publique du serveur puis chiffre et envoie la clé DES
    private fun getPublicAndSendDES() {
        val size = input.read()
        //on récupère la clé RSA publique du serveur
        publicRSA = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(input.readNBytes(size)))
        //on chiffre la clé DES avec la clé publique RSA
        val encrypter: Cipher = Cipher.getInstance("RSA")
        encrypter.init(Cipher.ENCRYPT_MODE, publicRSA)
        val crypted = encrypter.doFinal(keyDES.encoded)
        //on envoie la clé DES chiffrée au serveur
        output.write(crypted.size)
        output.write(crypted)
    }

    //écoute les message du serveur
    private fun listener() {
        while (true) {
            if (client.isClosed) break
            //on récupère le message du serveur déchiffré depuis l'input du serveur
            val response = input.readDecryptedBytes(keyDES)
            //on l'insère dans le champs de réponse
            serverResponse.text = response
        }
        client.close()
    }

    //fonction qui récupère les évènements de la fenêtre du client
    override fun actionPerformed(e: ActionEvent?) {
        if (e!!.source == sendButton) {
            //on récupère le texte de l'input lorsque l'utilisateur clique sur le boutton "envoyer"
            val text = clientInput.text
            if (text == "quit") {
                setVisible(false)
                dispose()
                client.close()
            } else {
                //on le chiffre et on l'envoit dans l'output de la socket
                output.writeEncrypted(text, keyDES)
                clientInput.text = ""
            }
        }
    }


}