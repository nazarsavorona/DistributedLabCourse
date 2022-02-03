package level1.hash;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

public class RSA {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final BigInteger privateKey;
    private final BigInteger publicKey;
    private final BigInteger modulus;

    RSA(int N) {
        BigInteger p = BigInteger.probablePrime(N / 2, RANDOM);
        BigInteger q = BigInteger.probablePrime(N / 2, RANDOM);
        BigInteger phi = (p.subtract(ONE)).multiply(q.subtract(ONE));

        modulus = p.multiply(q);
        publicKey = BigInteger.valueOf(65537);     // 65537 = 2^16 + 1
        privateKey = publicKey.modInverse(phi);
    }


    BigInteger encrypt(BigInteger message) {
        return message.modPow(publicKey, modulus);
    }

    BigInteger decrypt(BigInteger encrypted) {
        return encrypted.modPow(privateKey, modulus);
    }

    @Override
    public String toString() {
        return "RSA {" +
                "\nprivateKey = " + privateKey +
                ",\npublicKey = " + publicKey +
                ",\nmodulus = " + modulus +
                "\n}";
    }

    public static void main(String[] args) {
        int N = 0;

        if (args.length == 0) {
            Scanner input = new Scanner(System.in);
            System.out.print("N: ");
            N = input.nextInt();
            input.close();
        } else if (args.length == 1) {
            N = Integer.parseInt(args[0]);
            System.out.printf("N: %d%n", N);
        }
        RSA key = new RSA(N);

        String s = "Hello, Distributed Lab!";
        byte[] bytes = s.getBytes();
        BigInteger message = new BigInteger(bytes);

        BigInteger encrypt = key.encrypt(message);
        BigInteger decrypted = key.decrypt(encrypt);

        System.out.println(key);
        System.out.printf("message = %s%n", new String(message.toByteArray()));
        System.out.printf("encrypted = %s%n", new String(encrypt.toByteArray()));
        System.out.printf("decrypted = %s%n", new String(decrypted.toByteArray()));
    }
}
