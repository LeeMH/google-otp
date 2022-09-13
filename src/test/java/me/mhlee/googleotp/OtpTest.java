package me.mhlee.googleotp;

import me.mhlee.googleotp.Otp.QrSize;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class OtpTest {
    private static String USER = "hello";
    private static String PASSWORD = "world";

    @Test
    public void make100x100Qr() {
        String secret = Otp.makeSecret();
        String qrUrl = Otp.makeQrUrl(USER, PASSWORD, secret, QrSize.X100);

        System.out.println(String.format("Secret = [%s]", secret));
        System.out.println(String.format("QR = [%s]", qrUrl));

        assertFalse(Otp.verifyOtp(secret, -1));
    }

    @Test
    public void make200x200Qr() {
        String secret = Otp.makeSecret();
        String qrUrl = Otp.makeQrUrl(USER, PASSWORD, secret, QrSize.X200);

        System.out.println(String.format("Secret = [%s]", secret));
        System.out.println(String.format("QR = [%s]", qrUrl));

        assertFalse(Otp.verifyOtp(secret, -1));
    }

    @Test
    public void make300x300Qr() {
        String secret = Otp.makeSecret();
        String qrUrl = Otp.makeQrUrl(USER, PASSWORD, secret, QrSize.X300);

        System.out.println(String.format("Secret = [%s]", secret));
        System.out.println(String.format("QR = [%s]", qrUrl));

        assertFalse(Otp.verifyOtp(secret, -1));
    }

    @Test
    public void verifyOtp() {
        String secret = "Put Your Secret";
        long otp = -1; // put your otp code

        assertTrue(Otp.verifyOtp(secret, otp));
    }
}
