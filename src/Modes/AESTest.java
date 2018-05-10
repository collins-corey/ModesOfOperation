package Modes;

import java.io.IOException;

public class AESTest {
    public static void main(String[] args) throws IOException {
        // Created a interface to perform all the operations necessary for the program.
        ModesInterface mode;

        mode = new ECB();
        // Set the interface to be of the ECB type to perform ECB encryption and decryption.
        mode.readKey(args);// Reads the key and stores the value within the class.
        mode.encrypt(args);// Performs ECB based encryption.
        mode.writeCipher(args);// Writes the ciphertext Strings created to a text document.
        mode.decrypt(args);// Performs ECB based decryption.
        mode.writePlain(args);// Writes the deciphered plaintext string to a text document.

        mode = new CBC();
        // Set the interface to be of the CBC type to perform CBC encryption and decryption.
        mode.readKey(args);// Reads the key and stores the value within the class.
        mode.encrypt(args);// Performs CBC based encryption.
        mode.writeCipher(args);// Writes the ciphertext Strings created to a text document.
        mode.decrypt(args);// Performs CBC based decryption.
        mode.writePlain(args);// Writes the deciphered plaintext string to a text document.

        mode = new OFB();
        // Set the interface to be of the OFB type to perform OFB encryption and decryption.
        mode.readKey(args);// Reads the key and stores the value within the class.
        mode.encrypt(args);// Performs OFB based encryption.
        mode.writeCipher(args);// Writes the ciphertext Strings created to a text document.
        mode.decrypt(args);// Performs OFB based decryption.
        mode.writePlain(args);// Writes the deciphered plaintext string to a text document.

        mode = new CFB();
        // Set the interface to be of the CFB type to perform CFB encryption and decryption.
        mode.readKey(args);// Reads the key and stores the value within the class.
        mode.encrypt(args);// Performs CFB based encryption.
        mode.writeCipher(args);// Writes the ciphertext Strings created to a text document.
        mode.decrypt(args);// Performs CFB based decryption.
        mode.writePlain(args);// Writes the deciphered plaintext string to a text document.

        mode = new CTR();
        // Set the interface to be of the CTR type to perform CTR encryption and decryption.
        mode.readKey(args);// Reads the key and stores the value within the class.
        mode.encrypt(args);// Performs CTR based encryption.
        mode.writeCipher(args);// Writes the ciphertext Strings created to a text document.
        mode.decrypt(args);// Performs CTR based decryption.
        mode.writePlain(args);// Writes the deciphered plaintext string to a text document.
    }
}
