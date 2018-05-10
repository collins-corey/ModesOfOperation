package Modes;

import java.io.IOException;
import java.util.ArrayList;

public interface ModesInterface {
    // This method is used to read the file containing the key and store the value into each class to be used
    // for encryption and decryption.
    public void readKey(String[] args) throws IOException;

    // This method is used to encrypt the plaintext file based off the classes mode.
    public void encrypt(String[] args) throws IOException;

    // This method is used to decrypt the ciphertext file based off the classes mode.
    public void decrypt(String[] args) throws IOException;

    // This method is used to write the ciphertext generated from the encrypt method to a text document.
    public void writeCipher(String[] args) throws IOException;

    //This method is used to write the decrypted ciphertext generated from the decrypt method to a text document.
    public void writePlain(String[] args) throws IOException;
}
/*
XOR operation
byte a = 5;
byte b = 8;
byte c = (byte)(a ^ b);
*/
