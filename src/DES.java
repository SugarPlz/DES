import java.util.Scanner;

/**
 * @author Wang Zengke
 * @since 2022/11/28 17:17
 */
public class DES {
    //明文字符串64 bits----8 bytes
    private StringBuffer plaintext;
    //密文字符串64 bits----8 bytes
    private StringBuffer ciphertext;
    //密钥字符串64 bits ----8 bytes
    private StringBuffer key;
    //分组
    private int group;

    //IP置换
    private static final int[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
    };
    //IP逆置换
    private static final int[] IPReverse = {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25};
    // E位选择表(扩展置换表)
    private static final int[] E = {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1};
    //P换位表(单纯换位表)
    private static final int[] P = {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25};
    //PC1
    private static final int[] PC1 = {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4};
    // PC2
    private static final int[] PC2 = {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32};
    // SBox
    private static final int[][] SBox = {
            // S1
            {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
            // S2
            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
            // S3
            {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
            // S4
            {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
            // S5
            {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
            // S6
            {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
            // S7
            {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
            // S8
            {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};

    /**
     * StringBuffer转成二进制
     */
    public StringBuffer stringBufferToBinary(StringBuffer s) {
        StringBuffer res = new StringBuffer();
        StringBuffer stmp = new StringBuffer();
        for (int i = 0; i < s.length(); i++) {
            stmp = new StringBuffer(Integer.toBinaryString(s.charAt(i)));
            //转成8位二进制
            while (stmp.length() < 8) {
                stmp.insert(0, 0);
            }
            //System.out.println(stmp);
            res.append(stmp);
        }
        return res;
    }

    /**
     * 二进制字符串转成字符64->8
     */
    //int column = Integer.parseInt(sInput.substring(1, 5), 2);
    public StringBuffer BinaryToStringBuffer(StringBuffer s) {
        StringBuffer res = new StringBuffer();
        for (int i = 0; i < 8; i++) {
            int t = Integer.parseInt(s.substring(i * 8, (i + 1) * 8), 2);
            res.append((char) t);
        }
        return res;
    }

    /**
     * 初始置换IP
     */
    public StringBuffer Initial(StringBuffer r) {
        StringBuffer res = new StringBuffer();
        for (int i = 0; i < 64; i++) {
            //数组的索引是从0开始的
            res.append(r.charAt(IP[i] - 1));
        }
        return res;
    }

    /**
     * 终止置换IP
     */
    public StringBuffer Final(StringBuffer r) {
        StringBuffer res = new StringBuffer();
        for (int i = 0; i < 64; i++) {
            //数组的索引是从0开始的
            res.append(r.charAt(IPReverse[i] - 1));
        }
        return res;
    }

    /**
     * P置换
     */
    public StringBuffer p(StringBuffer r) {
        StringBuffer res = new StringBuffer();
        for (int i = 0; i < 32; i++) {
            //数组的索引是从0开始的
            res.append(r.charAt(P[i] - 1));
        }
        return res;
    }

    /**
     * 扩展置换（E表）
     */
    public StringBuffer extent(StringBuffer r) {
        StringBuffer res = new StringBuffer();
        for (int i = 0; i < 48; i++) {
            //数组的索引是从0开始的
            res.append(r.charAt(E[i] - 1));
        }
        return res;
    }

    /**
     * 密钥生成
     */
    public StringBuffer[] getSubkey() {
        //把密钥转成二进制
        StringBuffer keyBinary = new StringBuffer(stringBufferToBinary(key));
        //subkey数组用来存储子密钥
        StringBuffer subkey[] = new StringBuffer[16];
        //左密钥
        StringBuffer C0 = new StringBuffer();
        //右密钥
        StringBuffer D0 = new StringBuffer();
        //判断密钥长度
        while (keyBinary.length() < 64) {
            keyBinary.append("0");
        }
        //PC1置换（64 bits --> 56 bits）
        for (int i = 0; i < 28; i++) {
            C0.append(keyBinary.charAt(PC1[i] - 1));
            D0.append(keyBinary.charAt(PC1[i + 28] - 1));
        }
        //16轮循环生成子密钥
        //16轮移位操作，每轮左移一位，特殊情况左移两位（查看密钥移位表）
        for (int i = 0; i < 16; i++) {
            //把第一位删了添加到最后一位
            char tmp;
            tmp = C0.charAt(0);
            C0.deleteCharAt(0);
            C0.append(tmp);
            tmp = D0.charAt(0);
            D0.deleteCharAt(0);
            D0.append(tmp);
            //特殊位置左移两位
            if (i != 0 && i != 1 && i != 8 && i != 15) {
                tmp = C0.charAt(0);
                C0.deleteCharAt(0);
                C0.append(tmp);
                tmp = D0.charAt(0);
                D0.deleteCharAt(0);
                D0.append(tmp);
            }
            //左右合并
            StringBuffer CODO = new StringBuffer(C0.toString() + D0.toString());
            //PC2置换
            StringBuffer C0D0tmp = new StringBuffer();
            for (int j = 0; j < 48; j++) {
                C0D0tmp.append(CODO.charAt(PC2[j] - 1));
            }
            subkey[i] = C0D0tmp;
            //  System.out.println(i + "轮密钥：" + subkey[i]);
        }
        return subkey;
    }

    /**
     * f轮函数
     */
    public StringBuffer F(StringBuffer R, StringBuffer subkey) {
        StringBuffer res = new StringBuffer();
        //E盒扩展
        res = extent(R);
        //异或运算
        for (int i = 0; i < 48; i++) {
            res.replace(i, i + 1, (res.charAt(i) == subkey.charAt(i) ? "0" : "1"));
        }
        //S盒压缩
        //S盒用来接收压缩后的32 bits
        StringBuffer sBox = new StringBuffer();
        for (int i = 0; i < 8; i++) {
            String sInput = res.substring(i * 6, (i + 1) * 6);
            //首尾两位转化为行，中间四位转化为列
            //parseInt(String s,int radix)---把字符串s根据radix（进制）转成对应的整数
            int row = Integer.parseInt(Character.toString(sInput.charAt(0)) + sInput.charAt(5), 2);
            int column = Integer.parseInt(sInput.substring(1, 5), 2);
            StringBuffer sOutput = new StringBuffer(Integer.toBinaryString(SBox[i][row * 16 + column]));
            //小于四位要添0
            while (sOutput.length() < 4) {
                sOutput.insert(0, 0);
            }
            sBox.append(sOutput);
        }
        //P置换
        sBox = p(sBox);
        return sBox;
    }

    /**
     * 16轮迭代
     */
    public StringBuffer iteration(StringBuffer L, StringBuffer R, int mode) {
        StringBuffer res = new StringBuffer();
        //获取子密钥
        StringBuffer[] subkey = getSubkey();
        //mode == 1 解密  密钥反转
        if (mode == 1) {
            StringBuffer[] tmp = getSubkey();
            for (int i = 0; i < 16; i++) {
                subkey[i] = tmp[15 - i];
                //  System.out.println(i+"轮密钥："+subkey[i]);
            }
        }

        //查看密钥
//        for (int i =0;i<16;i++){
//            System.out.println(i+"轮密钥："+subkey[i]);
//        }

        //16轮循环
        for (int i = 0; i < 16; i++) {
            StringBuffer Ltmp = new StringBuffer(L);
            StringBuffer Rtmp = new StringBuffer(R);

            //右边的赋给左边
            L.replace(0, 32, R.toString());
            //F轮函数
            StringBuffer Fstring = F(Rtmp, subkey[i]);

            //Fstring异或R
            for (int j = 0; j < 32; j++) {
                R.replace(j, j + 1, (Fstring.charAt(j) == Ltmp.charAt(j) ? "0" : "1"));
            }
        }

        //循环结束后左右交换
        StringBuffer RL = new StringBuffer(R.toString() + L.toString());

        //终止置换
        RL = Final(RL);
        return RL;
    }

    public int getGroup() {
        return group;
    }

    //设置分组数
    public void setGroup() {
        group = plaintext.length() / 8;
    }

    public StringBuffer getPlaintext() {
        return plaintext;
    }

    public void setPlaintext(StringBuffer plaintext) {
        this.plaintext = plaintext;
    }

    public StringBuffer getCiphertext() {
        return ciphertext;
    }

    public void setCiphertext(StringBuffer ciphertext) {
        this.ciphertext = ciphertext;
    }

    public StringBuffer getKey() {
        return key;
    }

    public void setKey(StringBuffer key) {
        this.key = key;
    }
}