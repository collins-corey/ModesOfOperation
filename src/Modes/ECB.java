package Modes;

import java.io.*;
import java.util.ArrayList;


public class ECB implements ModesInterface {
    // Just listing variable i will use throughout the class.
    private AES aes = new AES();
    private BufferedReader br;
    private FileReader fr;
    private BufferedWriter bw;
    private FileWriter fw;
    private byte[] key;
    private byte[] plain = new byte[16];
    private String temp;
    private byte[] cipher;
    private ArrayList<String> tempByte = new ArrayList<>();
    private File file;

    public ECB(){

    }

    @Override
    public void readKey(String[] args) throws IOException {
        // This method reads the path location of a file from the command line containing the key for the encryption and decryption methods.
        file = new File(args[0]);
        fr = new FileReader(file);
        br = new BufferedReader(fr);

        while((temp = br.readLine()) != null){
            this.key = Util.hex2byte(temp);
        }
    }

    @Override
    public void encrypt(String[] args) throws IOException {
        // This method finds the file path for the plaintext file that will be used.
        // After finding the file it will perform the encryption based on the ECB mode.
        file = new File(args[1]);
        fr = new FileReader(file);
        br = new BufferedReader(fr);
        while((temp = br.readLine()) != null){
            plain = Util.hex2byte(temp.trim());// This changes the Hex string to a Byte array and trims any null values.
            aes.traceLevel = 1;// Sets the trace level to 1.
            aes.setKey(key);// Sets the key based off the one we extracted from the file.
            cipher = aes.encrypt(plain);// Performs the aes encryption.
            temp = Util.toHEX1(cipher);// Changes the return value to a hex string.
            tempByte.add(temp.trim());// Stores the hex string while trimming any null values in a temporary ArrayList to be used later.
        }
    }

    @Override
    public void decrypt(String[] args) throws IOException {
        // This method will pull in the file we created in our writeCipher method.
        // Then it will use the ciphertext strings created to be used for decryption.
        tempByte = new ArrayList<>();// Resets the ArrayList so its empty for the method.
        file = new File(args[2] + "ECB.txt");
        fr = new FileReader(file);
        br = new BufferedReader(fr);
        while((temp = br.readLine()) != null){
            // Same setup as the encryption except we use the decrypt method instead of the encrypt.
            cipher = Util.hex2byte(temp.trim());
            aes.traceLevel = 1;
            aes.setKey(key);
            plain = aes.decrypt(cipher);
            temp = Util.toHEX1(plain);
            tempByte.add(temp.trim());
        }
    }

    @Override
    public void writeCipher(String[] args) throws IOException {
        // This method uses the temporary ArrayList we created from the encrypt() method
        // to write the ciphertext strings to a text document.
        file = new File(args[2]+ "ECB.txt");
        fw = new FileWriter(file);
        bw = new BufferedWriter(fw);
        for(int i = 0; i < tempByte.size(); i++){
            bw.write(tempByte.get(i));
            // Created the if statement to keep from making extra lines in document.
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
        // This method is the same as writeCipher() but it uses the ArrayList created by the decrypt()
        // method to write the decrypted plaintext values to a text document.
        file = new File(args[2]+ "ECBdec.txt");
        fw = new FileWriter(file);
        bw = new BufferedWriter(fw);
        for(int i = 0; i < tempByte.size(); i++){
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