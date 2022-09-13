package me.mhlee.googleotp;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Date;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;

public class Otp {

    private static int DEFAULT_WINDOW_SIZE = 3;
    private static String GOOGLE_URL = "https://www.google.com/chart?chs=%s&chld=M|0&cht=qr&chl=";

    public enum QrSize {
        X100("100x100"),
        X200("200x200"),
        X300("300x300");

        private String size;

        QrSize(String size) {
            this.size = size;
        }
    }
    /**
     * Secret 생성
     * @return
     */
    public static String makeSecret() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[20];
        random.nextBytes(bytes);
        Base32 base32 = new Base32();
        return base32.encodeToString(bytes);
    }

    /**
     * QR 이미지 URL 생성
     * @return
     */
    public static String makeQrUrl(String user, String host, String secret) {
        return makeQrUrl(user, host, secret, QrSize.X200);
    }

    /**
     * QR 이미지 URL 생성 (with 사이즈 옵션)
     * @return
     */
    public static String makeQrUrl(String user, String host, String secret, QrSize qrSize) {
        try {
            return String.format(GOOGLE_URL, qrSize.size) + "otpauth://totp/"
                    + URLEncoder.encode(host + "@" + user, "UTF-8").replace("+", "%20")
                    + "?secret=" + URLEncoder.encode(secret, "UTF-8").replace("+", "%20")
                    + "&issuer=" + URLEncoder.encode(host, "UTF-8").replace("+", "%20");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * OTP 검증
     * @param secret
     * @param code
     * @return
     */
    public static boolean verifyOtp(String secret, long code) {
        return verifyOtp(secret, code, DEFAULT_WINDOW_SIZE);
    }

    /**
     * OTP 검증(with window size)
     * @param secret
     * @param code
     * @return
     */
    public static boolean verifyOtp(String secret, long code, int window) {
        long milliSec = new Date().getTime();
        long t =  milliSec / 30000;

        return _verityOtp(secret, code, t, window);
    }


    private static boolean _verityOtp(String secret, long code, long t, int window) {
        Base32 codec = new Base32();
        byte[] decodedKey = codec.decode(secret);

        // Window is used to check codes generated in the near past.
        // You can use this value to tune how far you're willing to go.
        for (int i = -window; i <= window; ++i) {
            long expectedOtp = _makeExpectedOtp(decodedKey, t + i);

            if (expectedOtp == code) {
                return true;
            }
        }

        // The validation code is invalid.
        return false;
    }

    /**
     * 검증용 OTP 생성
     * @param key
     * @param t
     * @return
     */
    private static int _makeExpectedOtp(byte[] key, long t) {
        byte[] data = new byte[8];
        long value = t;
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }
        SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
        Mac mac = null;
        try {
            mac = Mac.getInstance("HmacSHA1");
            mac.init(signKey);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        byte[] hash = mac.doFinal(data);

        int offset = hash[20 - 1] & 0xF;

        // We're using a long because Java hasn't got unsigned int.
        long truncatedHash = 0;
        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;
            truncatedHash |= (hash[offset + i] & 0xFF);
        }

        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= 1000000;

        return (int) truncatedHash;
    }
}
