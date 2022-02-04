package com.lyc;

import java.lang.reflect.Type;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

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

    /**
     * 将对象转化为Json字符串
     *
     * @author Dason
     * @param obj
     *            要转化的对象
     * @return 对象的Json字符串
     */
    public static String toJson(Object obj) {
        return gson.toJson(obj);
    }


}