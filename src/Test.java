import java.util.Scanner;

/**
 * @author Wang Zengke
 * @since 2022/11/28 17:29
 */
public class Test {
    public static void main(String[] args) {
        System.out.println("----DES----");
        //创建实例
        DES instance = new DES();

        //录入明文
        StringBuffer plain = new StringBuffer();
        //用来临时录入明文密文
        String tmp = "";
        Scanner sc = new Scanner(System.in);
        System.out.println("请输入明文：");
        tmp = sc.next();
        plain.append(tmp);
        //保存明文的长度
        int length = plain.length();
        instance.setPlaintext(plain);
        System.out.println("明文：" + instance.getPlaintext());

        //密钥产生
        System.out.println("输入密钥：");
        tmp = sc.next();
        StringBuffer mykey = new StringBuffer();
        mykey.append(tmp);
        instance.setKey(mykey);
        System.out.println("密钥：" + instance.getKey());

        //设置分组数
        instance.setGroup();

        //测试加密
        System.out.println("-----DES加密-----");
        plain = instance.stringBufferToBinary(instance.getPlaintext()); //明文转成二进制
        StringBuffer L = new StringBuffer();//左明文
        StringBuffer R = new StringBuffer();//右明文
        StringBuffer plainBackup = new StringBuffer(plain);  //二进制明文备份
        StringBuffer cipherBackup = new StringBuffer();  //二进制密文备份
        StringBuffer descipher = new StringBuffer(); //解密后的明文
        //扩充明文
        while (plainBackup.length() < 64 * (instance.getGroup() + 1)) {
            plainBackup.append("0");
        }
        //分组加密
        for (int i = 0; i <= instance.getGroup(); i++) {
            //明文分组处理
            for (int j = 0; j < 64; j++) {
                plain.replace(j, j + 1, plainBackup.substring(j + i * 64, j + 64 * i + 1));
            }

            //初始置换
            plain = instance.Initial(plain);

            L.replace(0, 32, plain.substring(0, 32));
            R.replace(0, 32, plain.substring(32, 64));

            //16轮迭代
            plain = instance.iteration(L, R, 0);//plain是加密后的二进制密文
            System.out.println(i + "轮迭代后：" + plain);

            //备份二进制密文
            cipherBackup.append(plain);
            System.out.println(i + "轮密文：" + instance.BinaryToStringBuffer(plain));
        }

        //测试解密
        System.out.println("-----DES解密-----");
        //分组解密
        for (int i = 0; i <= instance.getGroup(); i++) {
            //密文分组处理
            for (int j = 0; j < 64; j++) {
                plain.replace(j, j + 1, cipherBackup.substring(j + i * 64, j + 64 * i + 1));
            }

            //初始置换
            plain = instance.Initial(plain);

            L.replace(0, 32, plain.substring(0, 32));
            R.replace(0, 32, plain.substring(32, 64));
            plain = instance.iteration(L, R, 1);//plain是解密后的二进制密文
            System.out.println(i + "轮迭代后：" + plain);
            System.out.println(i + "明文：" + instance.BinaryToStringBuffer(plain));
            descipher.append(instance.BinaryToStringBuffer(plain));
        }
        //输出解密后的明文
        System.out.println("最终解密后的明文：" + descipher.substring(0, length));
    }
}
