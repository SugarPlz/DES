package DES.another;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;

/**
 *
 * https://www.cnblogs.com/haoxinyue/archive/2012/04/26/2470661.html
 * @author Wang Zengke
 * @since 2022/11/30 10:21
 */
public class AnotherDES {
    public static void main(String[] args) {
        String text = "测试asdY^&*NN!__s ?*（&……（%！（*#……#￥）（！@#￥ldfkhgsdf《》<>some plaintext!";
        System.out.println("加密前的明文:" + text);
        String cryperText = "";
        try {
            cryperText = toHexString(encrypt(text));
            System.out.println("加密前的明文:" + cryperText);
            byte[] encrypt = encrypt(cryperText);
            System.out.println(toHexString(encrypt));
            System.out.println("解密后的明文:" + decrypt(cryperText));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] desKey;
    private static String key = "19491001";

    public static String decrypt(String message) throws Exception {

        byte[] bytesrc = convertHexString(message);
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        DESKeySpec desKeySpec = new DESKeySpec(key.getBytes(StandardCharsets.UTF_8));
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = keyFactory.generateSecret(desKeySpec);
        IvParameterSpec iv = new IvParameterSpec(key.getBytes(StandardCharsets.UTF_8));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        byte[] retByte = cipher.doFinal(bytesrc);
        return new String(retByte);
    }

    public static byte[] encrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");

        DESKeySpec desKeySpec = new DESKeySpec(key.getBytes(StandardCharsets.UTF_8));

        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = keyFactory.generateSecret(desKeySpec);
        IvParameterSpec iv = new IvParameterSpec(key.getBytes(StandardCharsets.UTF_8));
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        return cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] convertHexString(String ss) {
        byte[] digest = new byte[ss.length() / 2];
        for (int i = 0; i < digest.length; i++) {
            String byteString = ss.substring(2 * i, 2 * i + 2);
            int byteValue = Integer.parseInt(byteString, 16);
            digest[i] = (byte) byteValue;
        }

        return digest;
    }

    public static String toHexString(byte[] b) {
        StringBuilder hexString = new StringBuilder();
        for (byte value : b) {
            String plainText = Integer.toHexString(0xff & value);
            if (plainText.length() < 2) {
                plainText = "0" + plainText;
            }
            hexString.append(plainText);
        }
        return hexString.toString();
    }

}