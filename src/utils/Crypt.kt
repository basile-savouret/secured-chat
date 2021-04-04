package utils

import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.Charset
import java.security.Key
import javax.crypto.Cipher

//fonctionnalité spécifique a kotlin qui permet d'ajouter une méthode à une class que l'on a pas écrite
//ici on ajoute une méthode pour recevoir des messages déchiffrés sur un InputStream
fun InputStream.readDecryptedBytes(key: Key): String {
    //on récupère le tableau de bites du message chiffré
    val size = this.read()
    val bytes = this.readNBytes(size)
    //on déchiffre avec la clé passer en paramètre et on retourne le message
    val decrypter: Cipher = Cipher.getInstance("DES")
    decrypter.init(Cipher.DECRYPT_MODE, key)
    val result = decrypter.doFinal(bytes)
    return result.toString(Charset.forName("UTF-8"))
}

//ici on ajoute une méthode pour envoyer des messages chiffrés sur un OutputStream
fun OutputStream.writeEncrypted(message: String, key: Key) {
    //on chiffre le message avec la clé passée en paramètre puis on l'envoie sur le stream
    val encrypter: Cipher = Cipher.getInstance("DES")
    encrypter.init(Cipher.ENCRYPT_MODE, key)
    val crypted = encrypter.doFinal(message.toByteArray())
    this.write(crypted.size)
    this.write(crypted)
}