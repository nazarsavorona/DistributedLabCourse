package level1.hash;

import java.util.ArrayList;
import java.util.List;

import static java.lang.Math.*;

public class SHA_1 {
    private final int BLOCK_SIZE = 512;
    private final int WORD_SIZE = 32;

    private String GetSHA_1Hash(String message) {
        int h0 = 0x67452301;
        int h1 = 0xEFCDAB89;
        int h2 = 0x98BADCFE;
        int h3 = 0x10325476;
        int h4 = 0xC3D2E1F0;
        int messageLengthInBits = message.length() * 8;

        String padded = padMessage(message, messageLengthInBits);
        List<List<Integer>> words = getMessageWords(padded);

        for (int i = 0; i < words.size(); i++) {
            List<Integer> schedule = new ArrayList<>(80);
            for (int j = 0; j < 16; j++) {
                schedule.add(words.get(i).get(j));
            }
            for (int j = 16; j < 80; j++) {
                schedule.add(Integer.rotateLeft(schedule.get(j - 3) ^ schedule.get(j - 8) ^ schedule.get(j - 14) ^ schedule.get(j - 16), 1));
            }

            int a = h0;
            int b = h1;
            int c = h2;
            int d = h3;
            int e = h4;

            int rotated = Integer.rotateLeft(h0, 5);

            for (int t = 0; t < 80; t++) {
                int T = (int)((Integer.rotateLeft(a, 5) + f_t(b, c, d, t) + e + K_t(t) + schedule.get(t)) % pow(2, 32));
                e = d;
                d = c;
                c = Integer.rotateLeft(b, 30);
                b = a;
                a = T;
            }

            /*for (int t = 0; t < 80; t++) {
                long f = 0;
                long k = 0;
                if(t < 20){
                    f = (b & c) | ((~b)&d);
                    k = 0x5A827999;
                }
                else if(t < 40){
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                }
                else if(t < 60){
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                }
                else if(t < 80){
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }

                long temp = (Long.rotateLeft(a, 5) + f + e + k + schedule.get(t)) % round(pow(2, 32));
                e = d;
                d = c;
                c = Long.rotateLeft(b, 30);
                b = a;
                a = temp;
            }*/

            h0 = (int)((h0 + a) % pow(2, 32));
            h1 = (int)((h1 + b) % pow(2, 32));
            h2 = (int)((h2 + c) % pow(2, 32));
            h3 = (int)((h3 + d) % pow(2, 32));
            h4 = (int)((h4 + e) % pow(2, 32));
        }

        return Long.toHexString(h0) + Long.toHexString(h1) + Long.toHexString(h2) + Long.toHexString(h3) + Long.toHexString(h4);
    }

    private List<List<Integer>> getMessageWords(String padded) {
        List<List<Integer>> words = new ArrayList<>(padded.length() / BLOCK_SIZE);

        for (int i = 0; i < padded.length() / BLOCK_SIZE; i++) {
            words.add(new ArrayList<>(16));
            for (int j = 0; j < 16; j++) {
                int shift = i * BLOCK_SIZE + j * WORD_SIZE;
                words.get(i).add(Integer.parseInt(Integer.toHexString(Integer.parseInt(padded.substring(shift, shift + WORD_SIZE), 2)), 16));
            }
        }

        return words;
    }

    private String padMessage(String message, int messageLengthInBits) {
        StringBuilder padded = new StringBuilder();

        for (char c : message.toCharArray()) {
            padded.append(String.format("%08d", Integer.parseInt(Integer.toBinaryString(c))));
        }

        padded.append('1');

        int k = 0;

        for (k = 0; k < BLOCK_SIZE; k++) {
            if ((messageLengthInBits + 1 + k) % BLOCK_SIZE == 448) {
                break;
            }
            padded.append('0');
        }

        padded.append(String.format("%064d", Integer.parseInt(Integer.toBinaryString(messageLengthInBits))));

        return padded.toString();
    }

    private Long ROTL(long x, int n, int w) {
        return (x << n) | (x >> (w - n));
    }

    private Integer f_t(int x, int y, int z, int t) {
        if (0 <= t && t <= 19) {
            return (x & y) ^ (x & z);
        }
        if (20 <= t && t <= 39) {
            return x ^ y ^ z;
        }
        if (40 <= t && t <= 59) {
            return (x & y) ^ (x & z) ^ (y & z);
        } else {
            return x ^ y ^ z;
        }
    }

    private Integer K_t(int t) {
        if (0 <= t && t <= 19) {
            return 0x5a827999;
        } else if (20 <= t && t <= 39) {
            return 0x6ed9eba1;
        } else if (40 <= t && t <= 59) {
            return 0x8f1bbcdc;
        } else {
            return 0xca62c1d6;
        }
    }

    public static void main(String[] args) {
        SHA_1 hasher = new SHA_1();

        System.out.println(hasher.GetSHA_1Hash("abc"));


    }
}

/*
function GetSHA1Hash (message)
    begin
        h0 = 0x67452301
        h1 = 0xEFCDAB89
        h2 = 0x98BADCFE
        h3 = 0x10325476
        h4 = 0xC3D2E1F0             //variables initialization
        ml = message length in bits

        break message into 512-bit chunks (after message processing)
        for each chunk
            break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
            for i from 16 to 79
        w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrot 5

        a = h0
            b = h1
            c = h2
            d = h3
            e = h4

            for i from 0 to 79 {
                if 0 ≤ i ≤ 19 then
                    f = (b and c) or ((not b) and d)
                    k = 0x5A827999
                else if 20 ≤ i ≤ 39
                    f = b xor c xor d
                    k = 0x6ED9EBA1
                else if 40 ≤ i ≤ 59
                    f = (b and c) or (b and d) or (c and d)
                    k = 0x8F1BBCDC
                else if 60 ≤ i ≤ 79
                    f = b xor c xor d
                    k = 0xCA62C1D6

                temp = (a leftrot 5) + f + e + k + w[i]
                e = d
        d = c
                c = b leftrotate 30
                b = a
        a = temp
        }
            h0 = h0 + a
            h1 = h1 + b
            h2 = h2 + c
            h3 = h3 + d
            h4 = h4 + e

hash = (h0 lshift 128) or (h1 lshift 96) or (h2 lshift 64) or (h3 lshift 32) or h4     // concat
 */