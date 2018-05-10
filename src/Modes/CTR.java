package Modes;

import java.io.*;
import java.util.ArrayList;

public class CTR implements ModesInterface {
    // Initialization of variables needed.
    private AES aes = new AES();
    private byte[] counter = new byte[16];
    public int count = 0;
    private BufferedReader br;
    private FileReader fr;
    private BufferedWriter bw;
    private FileWriter fw;
    private ArrayList<String> tempByte = new ArrayList<>();
    private byte[] key;
    private byte[] plain;
    private byte[] cipher;
    private byte[] si;
    private File file;
    private String temp;
    private String pad = "000000000000000000000000";

    public CTR(){ }

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
        // After finding the file it will perform the encryption based on the CTR mode.
        file = new File(args[1]);
        fr = new FileReader(file);
        br = new BufferedReader(fr);
        while((temp = br.readLine()) != null) {
            plain = Util.hex2byte(temp);// Stores a byte[] of plaintext from the file into a variable.
            counter = Util.hex2byte(pad + Util.toHEX1(count));// Using a Util method to turn the count value into a Hex String and appending to the pad to make a byte[].
            aes.traceLevel = 1;// Sets trace level to 1.
            aes.setKey(key);// Sets the key.
            si = aes.encrypt(counter);// Encrypts the counter byte[] we created.
            cipher = si;
            for(int i = 0; i < cipher.length; i++){
                cipher[i] = (byte)(cipher[i] ^ plain[i]);// XOR's the encrypted count with the plaintext.
            }
            temp = Util.toHEX1(cipher);// Changes the XOR'd value into a Hex String.
            tempByte.add(temp);// Stores the Hex String for later.
            count++;// Increments the count.
        }
    }

    @Override
    public void decrypt(String[] args) throws IOException {
        // This method will pull in the file we created in our writeCipher method.
        // Then it will decrypt based off the CTR mode decryption.
        count = 0;// resets the count.
        tempByte = new ArrayList<>();// resets the String ArrayList.
        file = new File(args[2] + "CTR.txt");
        fr = new FileReader(file);
        br = new BufferedReader(fr);
        while((temp = br.readLine()) != null){
            counter = Util.hex2byte(pad + Util.toHEX1(count));
            cipher = Util.hex2byte(temp);// Storing our ciphertext value int a byte[].
            aes.traceLevel = 1;// Sets trace level to 1.
            aes.setKey(key);// Sets key.
            si = aes.encrypt(counter);// Encrypts out padded counter value.
            plain = si;
            for(int i = 0; i < plain.length; i++){
                plain[i] = (byte)(plain[i] ^ cipher[i]);// XOR's the encrypted count with the ciphertext.
            }
            temp = Util.toHEX1(plain);// Changes the XOR'd value into a Hex String.
            tempByte.add(temp);// Stores the Hex String for later.
            count++;// Increments the count.
        }
    }

    @Override
    public void writeCipher(String[] args) throws IOException {
        file = new File(args[2]+ "CTR.txt");
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
        file = new File(args[2]+ "CTRdec.txt");
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
