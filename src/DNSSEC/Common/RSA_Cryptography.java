package DNSSEC.Common;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by arnob on 21/05/2017.
 * RSA Cryptography class for RSA encryption and decryption purpose
 * <p>
 * Acknowledgement: <a href="https://www.mkyong.com/java/java-asymmetric-cryptography-example/"> Mkyong.com</a>
 */
public class RSA_Cryptography {
    private Cipher cipher;

    public RSA_Cryptography() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.cipher = Cipher.getInstance("RSA");
    }

    //https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html
    public PrivateKey getPrivate(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    //https://docs.oracle.com/javase/8/docs/api/java/security/spec/X509EncodedKeySpec.html
    public PublicKey getPublic(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public void encryptFile(byte[] input, File output, PrivateKey key) throws IOException, GeneralSecurityException {
        this.cipher.init(Cipher.ENCRYPT_MODE, key);
        writeToFile(output, this.cipher.doFinal(input));
    }

    public void decryptFile(byte[] input, File output, PublicKey key) throws IOException, GeneralSecurityException {
        this.cipher.init(Cipher.DECRYPT_MODE, key);
        writeToFile(output, this.cipher.doFinal(input));
    }

    private void writeToFile(File output, byte[] toWrite) throws IllegalBlockSizeException, BadPaddingException, IOException {
        FileOutputStream fos = new FileOutputStream(output);
        fos.write(toWrite);
        fos.flush();
        fos.close();
    }

    public String encryptText(String msg, PublicKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        this.cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.encodeBase64String(cipher.doFinal(msg.getBytes("UTF-8")));
    }

    public String decryptText(String msg, PrivateKey key) throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        this.cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(Base64.decodeBase64(msg)), "UTF-8");
    }

    public String getSignatureFromHash(String msg, PrivateKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        this.cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.encodeBase64String(cipher.doFinal(msg.getBytes("UTF-8")));
    }

    public String getHashFromSignature(String msg, PublicKey key) throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        this.cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(Base64.decodeBase64(msg)), "UTF-8");
    }

    public byte[] getFileInBytes(File f) throws IOException {
        FileInputStream fis = new FileInputStream(f);
        byte[] fBytes = new byte[(int) f.length()];
        //noinspection ResultOfMethodCallIgnored
        fis.read(fBytes);
        fis.close();
        return fBytes;
    }

    /*public static void main(String[] args) throws Exception {
        RSA_Cryptography ac = new RSA_Cryptography();
        PrivateKey privateKey = ac.getPrivate("RSA_keyPair/privateKey");
        PublicKey publicKey = ac.getPublic("RSA_keyPair/publicKey");

        String msg = "Cryptography is fun!";
        String encrypted_msg = ac.encryptText(msg, publicKey);
        String decrypted_msg = ac.decryptText(encrypted_msg, privateKey);
        System.out.println("Original Message: " + msg + "\nEncrypted Message: " + encrypted_msg + "\nDecrypted Message: " + decrypted_msg);

        if (new File("RSA_keyPair/text.txt").exists()) {
            ac.encryptFile(ac.getFileInBytes(new File("RSA_keyPair/text.txt")), new File("RSA_keyPair/text_encrypted.txt"), privateKey);
            ac.decryptFile(ac.getFileInBytes(new File("RSA_keyPair/text_encrypted.txt")), new File("RSA_keyPair/text_decrypted.txt"), publicKey);
        } else {
            System.out.println("Create a file text.txt under folder RSA_keyPair");
        }
    }*/
}
