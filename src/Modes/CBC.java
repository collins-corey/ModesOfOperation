package Modes;

import java.security.SecureRandom;
import java.io.*;
import java.util.ArrayList;

public class CBC implements ModesInterface {
    // Initializing the variables I will use.
    private SecureRandom rand = new SecureRandom();
    private byte[] IV = new byte[16];
    private AES aes = new AES();
    private byte[] cipher;
    private BufferedReader br;
    private FileReader fr;
    private BufferedWriter bw;
    private FileWriter fw;
    private ArrayList<String> tempByte = new ArrayList<>();
    private String temp;
    private byte[] key;
    private byte[] plain;
    private byte[] encrypted;
    private byte[] XOR = new byte[16];
    private byte[] pastCipher;
    private ArrayList<byte[]> previousCipher = new ArrayList<>();
    private int count = 0;
    private File file;

    public CBC() { rand.nextBytes(IV); }

    @Override
    public void readKey(String[] args) throws IOException {
        // Basic method to read and store the key from the text document.
        file = new File(args[0]);
        fr = new FileReader(file);
        br = new BufferedReader(fr);

        while ((temp = br.readLine()) != null) {
            this.key = Util.hex2byte(temp);
        }
    }

    @Override
    public void encrypt(String[] args) throws IOException {
        // This method finds the file path for the plaintext file that will be used.
        // After finding the file it will perform the encryption based on the CBC mode.
        count = 0; // Set a count to distinguish between first and general blocks.
        file = new File(args[1]);
        fr = new FileReader(file);
        br = new BufferedReader(fr);
        while ((temp = br.readLine()) != null) {
            plain = Util.hex2byte(temp.trim());
            if (count == 0) {
                // First blocks encryption.
                for (int i = 0; i < XOR.length; i++) {
                    XOR[i] = (byte)(plain[i] ^ IV[i]);// XOR function with the IV.
                }
                aes.traceLevel = 1;// Sets trace level to 1.
                aes.setKey(key);// Sets the key.
                encrypted = aes.encrypt(XOR);// Uses AES encryption on array from XOR function
                temp = Util.toHEX1(encrypted);// Turns the byte[] to a hex string to be stored in an ArrayList
            }
            else {
                // General blocks encryption.
                pastCipher = previousCipher.get(count - 1);// Stores the last ciphertext produced into a variable.
                for (int i = 0; i < XOR.length; i++) {
                    XOR[i] = (byte)(plain[i] ^ pastCipher[i]);// XOR function with the previous blocks ciphertext.
                }
                aes.traceLevel = 1;// sets trace level to 1.
                aes.setKey(key);// sets key.
                encrypted = aes.encrypt(XOR);// encrypts byte[] from XOR function.
                temp = Util.toHEX1(encrypted);// Turns the byte[] to a hex string to be stored in an ArrayList
            }
            previousCipher.add(encrypted);// Stores the cipher byte[] to be used in next block.
            tempByte.add(temp.trim());// Stores hex string to be used when writing to the text document.
            count++;// increments the count after each line is read.
        }
    }

    @Override
    public void decrypt(String[] args) throws IOException {
        // This method will pull in the file we created in our writeCipher method.
        // Then it will decrypt based off the CBC mode decryption.
        count = 0;// Sets count back to 0.
        tempByte = new ArrayList<>();// Resets our String array.
        previousCipher = new ArrayList<>();// Resets the array to store the previous rounds ciphers.
        file = new File(args[2] + "CBC.txt");
        fr = new FileReader(file);
        br = new BufferedReader(fr);
        while ((temp = br.readLine()) != null) {
            cipher = Util.hex2byte(temp.trim());// Pulls the ciphertext and turns it into a byte[].
            previousCipher.add(cipher);// Stores the ciphertext to be used later.
            if (count == 0) {
                aes.traceLevel = 1;// Sets trace level to 1.
                aes.setKey(key);// Sets key.
                encrypted = aes.decrypt(cipher);// Decrypts the ciphertext.
                for (int i = 0; i < XOR.length; i++) {
                    XOR[i] = (byte)(encrypted[i] ^ IV[i]);// XOR function to XOR the decrypted ciphertext with the IV.
                }
                temp = Util.toHEX1(XOR);// Turns byte[] to a String to be stored for later.
            } else {
                pastCipher = previousCipher.get(count - 1);// Gets the previous ciphertext to store in a variable.
                aes.traceLevel = 1;// Sets trace level to 1.
                aes.setKey(key);// Sets key.
                encrypted = aes.decrypt(cipher);// Decrypts the ciphertext.
                for (int i = 0; i < XOR.length; i++) {
                    XOR[i] = (byte)(encrypted[i] ^ pastCipher[i]);// XOR function to XOR the decrypted ciphertext with the previous ciphertext.
                }
                temp = Util.toHEX1(XOR);// Turns byte[] to a String to be stored for later.
            }
            tempByte.add(temp.trim());// Stores the string to be written to a text document later.
            count++;// increments the count.
        }
    }


    @Override
    public void writeCipher(String[] args) throws IOException {
        file = new File(args[2]+ "CBC.txt");
        fw = new FileWriter(file);
        bw = new BufferedWriter(fw);
        for (int i = 0; i < tempByte.size(); i++) {
            bw.write(tempByte.get(i));
            if( i + 1 != tempByte.size()){
                bw.newLine();
            }
        }
        bw.flush();
        fw.close();
        bw.close();
    }


    @Override
    public void writePlain(String[] args) throws IOException {
        file = new File(args[2]+ "CBCdec.txt");
        fw = new FileWriter(file);
        bw = new BufferedWriter(fw);
        for (int i = 0; i < tempByte.size(); i++){
            bw.write(tempByte.get(i));
            if( i + 1 != tempByte.size()){
                bw.newLine();
            }
        }
        bw.flush();
        fw.close();
        bw.close();
    }
}
