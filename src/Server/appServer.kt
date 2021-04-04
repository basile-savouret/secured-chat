package Server

//Le main qui permet de démarrer le serveur et son interface
fun main() {
    val myServer = Server(port = 3000)
    myServer.start()
}