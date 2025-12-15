package com.haotong.passwordchecker;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * A password analysis utility that computes the minimal Euclidean distance
 * between a password's "affinity mask" and a set of precomputed cluster centers.
 *
 * <p>This class is implemented as a Singleton. Use
 * {@link #getInstance()} or {@link #getInstance(File)} to obtain the shared instance.</p>
 *
 * <p>The cluster centers are loaded either from a CSV file located in the
 * classpath (default) or from a user-provided CSV file.</p>
 *
 * <p>In addition, this class provides a static helper method
 * {@link #ComputeMD5(String)} for computing the MD5 hash of a given string.</p>
 */
public class AwesomePasswordChecker {

    /**
     * Singleton instance of {@code AwesomePasswordChecker}.
     */
    private static AwesomePasswordChecker instance;

    /**
     * List of cluster centers, each represented as a vector of {@code double} values.
     */
    private final List<double[]> clusterCenters = new ArrayList<>();

    /**
     * Returns the singleton instance using a custom cluster-centers file.
     * <p>
     * This method will create the singleton the first time it is called, by
     * loading cluster centers from the given CSV file. Subsequent calls will
     * return the already initialized instance and ignore the file parameter.
     * </p>
     *
     * @param file CSV file containing the cluster center vectors separated by semicolons
     * @return the shared {@code AwesomePasswordChecker} instance
     * @throws IOException if the file cannot be opened or parsed
     */
    public static AwesomePasswordChecker getInstance(File file) throws IOException {
        if (instance == null) {
            instance = new AwesomePasswordChecker(new FileInputStream(file));
        }
        return instance;
    }

    /**
     * Returns the singleton instance using the default cluster-centers resource.
     * <p>
     * The cluster centers are loaded from the classpath resource
     * {@code cluster_centers_HAC_aff.csv}. The resource is expected to contain
     * one center vector per line, with elements separated by semicolons.
     * </p>
     *
     * @return the shared {@code AwesomePasswordChecker} instance
     * @throws IOException if the resource cannot be found or parsed
     */
    public static AwesomePasswordChecker getInstance() throws IOException {//AwesomePasswordChecker
        if (instance == null) {
            InputStream is = AwesomePasswordChecker.class
                    .getClassLoader()
                    .getResourceAsStream("cluster_centers_HAC_aff.csv");
            instance = new AwesomePasswordChecker(is);
        }
        return instance;
    }

    /**
     * Creates a new {@code AwesomePasswordChecker} and loads cluster centers
     * from the given input stream.
     *
     * <p>The input stream is assumed to provide CSV content where each line
     * represents one cluster center, and values are separated by semicolons.</p>
     *
     * @param is input stream containing the cluster centers in CSV format
     * @throws IOException if an error occurs while reading the input stream
     */
    private AwesomePasswordChecker(InputStream is) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(is));
        String line;
        while ((line = br.readLine()) != null) {
            String[] values = line.trim().split("[,;]");
            double[] center = new double[values.length];

            for (int i = 0; i < values.length; ++i) {
                center[i] = Double.parseDouble(values[i]);
            }
            clusterCenters.add(center);
        }
        br.close();
    }

    /**
     * Builds the "affinity mask" for a given password.
     *
     * <p>The mask is an integer array of length 28, where each position encodes
     * the character type of the corresponding password character using a small
     * integer code:</p>
     *
     * <ul>
     *   <li>{@code 1} – very common lowercase letters ({@code e, s, a, i, t, n, r, u, o, l})</li>
     *   <li>{@code 2} – other lowercase letters</li>
     *   <li>{@code 3} – very common uppercase letters ({@code E, S, A, I, T, N, R, U, O, L})</li>
     *   <li>{@code 4} – other uppercase letters</li>
     *   <li>{@code 5} – digits</li>
     *   <li>{@code 6} – selected punctuation characters
     *       ({@code >, <, -, ?, ., /, !, %, @, &})</li>
     *   <li>{@code 7} – any other character</li>
     * </ul>
     *
     * <p>If the password is shorter than 28 characters, the remaining positions
     * are left as {@code 0}. Characters beyond the 28th are ignored.</p>
     *
     * @param password the password to analyze
     * @return an integer array of length 28 representing the affinity mask
     */
    public int[] maskAff(String password) {
        int[] maskArray = new int[28];
        int limit = Math.min(password.length(), 28);

        for (int i = 0; i < limit; ++i) {
            char c = password.charAt(i);
            switch (c) {
                case 'e':
                case 's':
                case 'a':
                case 'i':
                case 't':
                case 'n':
                case 'r':
                case 'u':
                case 'o':
                case 'l':
                    maskArray[i] = 1;
                    break;
                case 'E':
                case 'S':
                case 'A':
                case 'I':
                case 'T':
                case 'N':
                case 'R':
                case 'U':
                case 'O':
                case 'L':
                    maskArray[i] = 3;
                    break;
                case '>':
                case '<':
                case '-':
                case '?':
                case '.':
                case '/':
                case '!':
                case '%':
                case '@':
                case '&':
                    maskArray[i] = 6;
                    break;
                default:
                    if (Character.isLowerCase(c)) {
                        maskArray[i] = 2;
                    } else if (Character.isUpperCase(c)) {
                        maskArray[i] = 4;
                    } else if (Character.isDigit(c)) {
                        maskArray[i] = 5;
                    } else {
                        maskArray[i] = 7;
                    }
            }
        }
        return maskArray;
    }

    /**
     * Computes the minimal Euclidean distance between the affinity mask of the
     * given password and all preloaded cluster centers.
     *
     * <p>The password is first transformed into an affinity mask via
     * {@link #maskAff(String)}, and then the Euclidean distance is evaluated
     * against each cluster center. The smallest distance is returned.</p>
     *
     * @param password the password whose distance to cluster centers is evaluated
     * @return the minimal Euclidean distance between the password mask and any cluster center
     */
    public double getDistance(String password) {
        int[] maskArray = maskAff(password);
        double minDistance = Double.MAX_VALUE;
        for (double[] center : clusterCenters) {
            minDistance = Math.min(euclideanDistance(maskArray, center), minDistance);
        }
        return minDistance;
    }

    /**
     * Computes the Euclidean distance between an integer vector and a double vector.
     *
     * <p>Both vectors are expected to have the same length. The method performs
     * a component-wise accumulation and returns the square root of the sum.</p>
     *
     * @param a the first vector, represented as an array of integers
     * @param b the second vector, represented as an array of doubles
     * @return the Euclidean distance between the two vectors
     */
    private double euclideanDistance(int[] a, double[] b) {
        double sum = 0;
        for (int i = 0; i < a.length; i++) {
            double diff = a[i] - b[i];
            sum += diff * diff;      // (a[i] - b[i])²
        }
        return Math.sqrt(sum);
    }


    /**
     * Computes the MD5 hash of the given input string and returns it as a
     * lowercase hexadecimal string.
     *
     * <p>This is a manual implementation of the MD5 algorithm. It:
     * <ol>
     *   <li>Encodes the input as bytes</li>
     *   <li>Applies MD5 padding (including the message length in bits)</li>
     *   <li>Processes the message in 512-bit blocks</li>
     *   <li>Produces a 128-bit (16-byte) digest</li>
     * </ol>
     * The final digest is then converted to a 32-character hex string.</p>
     *
     * <p><strong>Note:</strong> MD5 is considered cryptographically broken and
     * should not be used for security-critical purposes such as password storage.
     * It is still acceptable for non-security uses like checksums.</p>
     *
     * @param input the input string whose MD5 hash is to be computed
     * @return the MD5 hash represented as a 32-character lowercase hexadecimal string
     */
    public static String ComputeMD5(String input) {
        byte[] message = input.getBytes();
        int messageLenBytes = message.length;

        int numBlocks = ((messageLenBytes + 8) >>> 6) + 1;
        int totalLen = numBlocks << 6;
        byte[] paddingBytes = new byte[totalLen - messageLenBytes];
        paddingBytes[0] = (byte) 0x80;

        long messageLenBits = (long) messageLenBytes << 3;
        ByteBuffer lengthBuffer = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(messageLenBits);
        byte[] lengthBytes = lengthBuffer.array();

        byte[] paddedMessage = new byte[totalLen];
        System.arraycopy(message, 0, paddedMessage, 0, messageLenBytes);
        System.arraycopy(paddingBytes, 0, paddedMessage, messageLenBytes, paddingBytes.length);
        System.arraycopy(lengthBytes, 0, paddedMessage, totalLen - 8, 8);

        int[] h = {
                0x67452301,
                0xefcdab89,
                0x98badcfe,
                0x10325476
        };

        int[] k = {
                0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
        };

        int[] r = {
                7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
        };

        for (int i = 0; i < numBlocks; i++) {
            int[] w = new int[16];
            for (int j = 0; j < 16; j++) {
                w[j] = ByteBuffer
                        .wrap(paddedMessage, (i << 6) + (j << 2), 4)
                        .order(ByteOrder.LITTLE_ENDIAN)
                        .getInt();
            }

            int a = h[0];
            int b = h[1];
            int c = h[2];
            int d = h[3];

            for (int j = 0; j < 64; j++) {
                int f, g;
                if (j < 16) {
                    f = (b & c) | (~b & d);
                    g = j;
                } else if (j < 32) {
                    f = (d & b) | (~d & c);
                    g = (5 * j + 1) % 16;
                } else if (j < 48) {
                    f = b ^ c ^ d;
                    g = (3 * j + 5) % 16;
                } else {
                    f = c ^ (b | ~d);
                    g = (7 * j) % 16;
                }
                int temp = d;
                d = c;
                c = b;
                b = b + Integer.rotateLeft(a + f + k[j] + w[g], r[j]);
                a = temp;
            }

            h[0] += a;
            h[1] += b;
            h[2] += c;
            h[3] += d;
        }

        // Step 5: Output
        ByteBuffer md5Buffer = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        md5Buffer.putInt(h[0]).putInt(h[1]).putInt(h[2]).putInt(h[3]);
        byte[] md5Bytes = md5Buffer.array();

        StringBuilder md5Hex = new StringBuilder();
        for (byte b : md5Bytes) {
            md5Hex.append(String.format("%02x", b));
        }

        return md5Hex.toString();
    }
}
