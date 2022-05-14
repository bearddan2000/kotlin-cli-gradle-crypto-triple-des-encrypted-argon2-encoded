package example;


import java.security.MessageDigest;
//import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

class Encryption{

  val digestName = "md5";
  val digestPassword = "HG58YZ3CR9";
  val key = setupSecretKey();
  val iv = IvParameterSpec(ByteArray(8));

    @Throws(Exception::class)
    fun setupSecretKey(): SecretKey {
        val md = MessageDigest.getInstance(digestName);
        val digestOfPassword = md.digest(digestPassword.toByteArray());
        var keyBytes = digestOfPassword.clone() + ByteArray(8)
        for(j in 0..8){
          keyBytes[j+15] = keyBytes[j]
        }

        return SecretKeySpec(keyBytes, "DESede");
    }

    @Throws(Exception::class)
    fun setupCipher(optMode: Int): Cipher {
      val cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
      cipher.init(optMode, key, iv);
      return cipher;
    }

    @Throws(Exception::class)
    fun encryptPasswordBased(plainText :String) : String
    {
        val cipher = setupCipher(Cipher.ENCRYPT_MODE);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.toByteArray()))
    }

    @Throws(Exception::class)
    fun decryptPasswordBased(cipherText: String): String  {
      val cipher = setupCipher(Cipher.DECRYPT_MODE);
      return String(cipher.doFinal(Base64.getDecoder().decode(cipherText)));
    }

}
