package example

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

import java.io.IOException;
import java.security.KeyPair;
import javax.xml.bind.DatatypeConverter;

class Encode(
  var argon2: Argon2,
  var encryption: Encryption
) {

  constructor(): this(
    Argon2Factory.create(),
    Encryption()
  )

  @Throws ( Exception::class  )
  fun encrypt(plainText: String): String { return encryption.encryptPasswordBased(plainText);}

  @Throws ( Exception::class  )
  fun decrypt(cipherText: String): String { return encryption.decryptPasswordBased(cipherText);}

  fun hashpw(pass: String): String {

    val passwordChars = pass.toCharArray();

    val stored = argon2.hash(22, 65536, 1, passwordChars);

    argon2.wipeArray(passwordChars);

    try {

      return encrypt(stored);

    } catch (e: Exception) {

      return "";
    }
  }

  fun verify(pass :String, hash: String): Boolean {
      try{

        val newHash = decrypt(hash);

        return argon2.verify(newHash, pass.toCharArray());

    } catch (e: Exception) {
        return false;
    }
  }
}
