package Server

import java.io.*
import java.net.Socket
import java.security.Key

//class utilitaire pour sauvegarder les données de chaques client du serveur
data class ServerClient(
    val socket: Socket,
    val output: OutputStream,
    val input: InputStream,
    val keyDES: Key,
    var lastMessage: String? = ""
)