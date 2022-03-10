package com.lyc.util;

/**
 * @author ：刘煜澄
 * @date ：Created in 2022/1/13 3:29 PM
 * @description：
 */

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Type;

public class GsonUtil {

    private static Logger logger = LoggerFactory.getLogger(GsonUtil.class);

    private static Gson gson = new Gson();

    private static Gson gson1 = new GsonBuilder().disableHtmlEscaping().create();

    @SuppressWarnings("unchecked")
    public static <T> T fromJsonWithDisableHtmlEscaping(String str, Type t) {
        try {
            return (T) gson1.fromJson(str, t);
        } catch (Exception ex) {
            logger.error("Error when parse string " + str + "to type #" + t, ex);
        }
        return null;
    }

    public static String toJson(Object obj) {
        return gson.toJson(obj);
    }


}