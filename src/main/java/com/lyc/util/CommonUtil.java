package com.lyc.util;

import java.util.Random;

public class CommonUtil {
    public static String createNonceStr(int length) {
        String sl = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder bf = new StringBuilder();
        for (int i = 0; i < length; i++) {
            bf.append(sl.charAt(new Random().nextInt(sl.length())));
        }
        return bf.toString();
    }

    public static String createSM4Key() {
        String sl = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder bf = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            bf.append(sl.charAt(new Random().nextInt(sl.length())));
        }
        return bf.toString();
    }
}
