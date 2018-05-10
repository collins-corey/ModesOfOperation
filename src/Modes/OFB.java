package Modes;

import java.security.SecureRandom;
import java.io.*;
import java.util.ArrayList;

public class OFB implements ModesInterface {
    // Initialization of variables.
    private SecureRandom rand = new SecureRandom();
    private byte[] IV = new byte[16];
    private AES aes = new AES();
    private byte[] si;
    private byte[] cipher = new byte[16];
    private BufferedReader br;
    private FileReader fr;
    private BufferedWriter bw;
    private FileWriter fw;
    private ArrayList<String> tempByte = new ArrayList<>();
    private ArrayList<byte[]> siTemp = new ArrayList<>();
    private File file;
    private String temp;
    private byte[] key;
    private byte[] plain;
    private int count = 0;

    public OFB(){ rand.nextBytes(IV); }

    @Override
    public void readKey(String[] args) throws IOException {
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
        // After finding the file it will perform the encryption based on the OFB mode.
        file = new File(args[1]);
        fr = new FileReader(file);
        br = new BufferedReader(fr);
        while((temp = br.readLine()) != null) {
            plain = Util.hex2byte(temp);// Stores the plaintext byte[] into a variable.
            if (count == 0) {
                // First block encryption.
                aes.traceLevel = 1;// Sets trace level to 1.
                aes.setKey(key);// Sets key.
                si = aes.encrypt(IV);// Encrypts the IV value.
                siTemp.add(si);// Adds the encrypted value to an ArrayList to be used later.
                for(int i = 0; i < si.length; i++){
                    cipher[i] = (byte)(si[i] ^ plain[i]);// XOR function that XOR's the encypted IV with the plaintext.
                }
                temp = Util.toHEX1(cipher);// Turns XOR'd byte[] to a Hex String.
            }
            else{
                // General block encryption.
                aes.traceLevel = 1;// Sets trace level to 1.
                aes.setKey(key);// Sets key.
                si = aes.encrypt((siTemp.get(count - 1)));// Gets previous si value and encrypts it.
                siTemp.add(si);// Adds encrypted si to be used later.
                for(int i = 0; i < si.length; i++){
                    cipher[i] = (byte)(si[i] ^ plain[i]);// XOR function that XOR's the encrypted si with the plaintext.
                }
                temp = Util.toHEX1(cipher);// Turns XOR'd byte[] to a Hex String.
            }
            tempByte.add(temp);// Stores Hex String value for write method.
            count ++;// Increments count.
        }
    }

    @Override
    public void decrypt(String[] args) throws IOException {
        // This method will pull in the file we created in our writeCipher method.
        // Then it will decrypt based off the OFB mode decryption.
        // Most of the code is similar so I will document the parts that are different.
        siTemp = new ArrayList<>();// Resets the array.
        tempByte = new ArrayList<>();// Resets the array.
        count = 0;// Resets the count.
        file = new File(args[2] + "OFB.txt");
        fr = new FileReader(file);
        br = new BufferedReader(fr);
        while((temp = br.readLine()) != null){
            cipher = Util.hex2byte(temp);// Stores the ciphertext byte[] into a variable.
            if (count == 0){
                // First Block decryption.
                // The only difference in the First block decryption is the XOR function.
                // Instead of XORing with the plain text you will XOR with the ciphertext.
                aes.traceLevel = 1;
                aes.setKey(key);
                si = aes.encrypt(IV);
                siTemp.add(si);
                for(int i = 0; i < si.length; i++){
                    plain[i] = (byte)(si[i] ^ cipher[i]);
                }
                temp = Util.toHEX1(plain);
            }
            else{
                // General Block decryption.
                // The only difference in the General block decryption is the XOR function.
                // Instead of XORing with the plain text you will XOR with the ciphertext.
                aes.traceLevel = 1;
                aes.setKey(key);
                si = aes.encrypt((siTemp.get(count - 1)));
                siTemp.add(si);
                for(int i = 0; i < si.length; i++){
                    plain[i] = (byte)(si[i] ^ cipher[i]);
                }
                temp = Util.toHEX1(plain);
            }
            tempByte.add(temp);
            count ++;
        }
    }

    @Override
    public void writeCipher(String[] args) throws IOException {
        file = new File(args[2]+ "OFB.txt");
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

    @Override
    public void writePlain(String[] args) throws IOException {
        file = new File(args[2]+ "OFBdec.txt");
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