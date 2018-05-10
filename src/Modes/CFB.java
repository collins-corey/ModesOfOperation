package Modes;

import java.security.SecureRandom;
import java.io.*;
import java.util.ArrayList;

public class CFB implements ModesInterface {
    private SecureRandom rand = new SecureRandom();
    private byte[] IV = new byte[16];
    private AES aes = new AES();
    private byte[] cipher;
    private BufferedReader br;
    private FileReader fr;
    private BufferedWriter bw;
    private FileWriter fw;
    private ArrayList<String> tempByte = new ArrayList<>();
    private byte[] key;
    private byte[] plain;
    private byte[] XOR = new byte[16];
    private File file;
    private String temp;
    private int count = 0;
    private ArrayList<byte[]> pastCipher = new ArrayList<>();
    private byte[] si;

    public CFB(){ rand.nextBytes(IV); }

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
        // After finding the file it will perform the encryption based on the CFB mode.
        file = new File(args[1]);
        fr = new FileReader(file);
        br = new BufferedReader(fr);
        while((temp = br.readLine()) != null) {
            plain = Util.hex2byte(temp.trim());// Stores the plaintext byte[] into a variable.
            if (count == 0) {
                // First Block encryption.
                aes.traceLevel = 1;// Sets trace level to 1.
                aes.setKey(key);// Sets key.
                si = aes.encrypt(IV);// Encrypts IV.
                for(int i = 0; i < XOR.length; i++){
                    XOR[i] = (byte)(si[i] ^ plain[i]);// XOR's the encrypted IV and the plaintext byte[].
                }
                temp = Util.toHEX1(XOR);// Turns XOR'd byte[] to a Hex String.
            }
            else{
                // General Block decryption.
                aes.traceLevel = 1;
                aes.setKey(key);
                si = aes.encrypt((pastCipher.get(count - 1)));// Gets the previous ciphertext value to store in a variable.
                for(int i = 0; i < XOR.length; i++){
                    XOR[i] = (byte)(si[i] ^ plain[i]);// XOR's the encrypted previous ciphertext and the plaintext byte[].
                }
                temp = Util.toHEX1(XOR);// Turns XOR'd byte[] to a Hex String.
            }
            pastCipher.add(XOR);// Stores the ciphertext byte[] to be used again.
            tempByte.add(temp);// Stores the Hex String value of the ciphertext.
            count ++;// Increments the count.
        }
    }

    @Override
    public void decrypt(String[] args) throws IOException {
        // This method will pull in the file we created in our writeCipher method.
        // Then it will decrypt based off the CFB mode decryption.
        // Most of the code is similar so I will document the parts that are different.
        pastCipher = new ArrayList<>();
        tempByte = new ArrayList<>();
        count = 0;
        file = new File(args[2] + "CFB.txt");
        fr = new FileReader(file);
        br = new BufferedReader(fr);
        while((temp = br.readLine()) != null){
            cipher = Util.hex2byte(temp.trim());
            pastCipher.add(cipher);// Stores the ciphertext byte[] to be used in decryption.
            if (count == 0){
                // First Block decryption.
                aes.traceLevel = 1;
                aes.setKey(key);
                si = aes.encrypt(IV);
                for(int i = 0; i < XOR.length; i++){
                    XOR[i] = (byte)(si[i] ^ cipher[i]);// XOR's encrypted IV with the ciphertext.
                }
                temp = Util.toHEX1(XOR);
            }
            else{
                // General Block decryption.
                aes.traceLevel = 1;
                aes.setKey(key);
                si = aes.encrypt((pastCipher.get(count - 1)));
                for(int i = 0; i < XOR.length; i++){
                    XOR[i] = (byte)(si[i] ^ cipher[i]);// XOR's the encrypted previous ciphertext with the ciphertext.
                }
                temp = Util.toHEX1(XOR);
            }
            tempByte.add(temp);
            count ++;
        }
    }

    @Override
    public void writeCipher(String[] args) throws IOException {
        file = new File(args[2]+ "CFB.txt");
        fw = new FileWriter(file);
        bw = new BufferedWriter(fw);
        for(int i = 0; i < tempByte.size(); i++){
            bw.write(tempByte.get(i));
            bw.newLine();
        }
        bw.flush();
        fw.close();
        bw.close();
    }

    @Override
    public void writePlain(String[] args) throws IOException {
        file = new File(args[2]+ "CFBdec.txt");
        fw = new FileWriter(file);
        bw = new BufferedWriter(fw);
        for(int i = 0; i < tempByte.size(); i++){
            bw.write(tempByte.get(i));
            bw.newLine();
        }
        bw.flush();
        fw.close();
        bw.close();
    }
}
