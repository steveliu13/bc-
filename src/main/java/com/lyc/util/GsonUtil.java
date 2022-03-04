package com.lyc.util;

/**
 * @author ：刘煜澄
 * @date ：Created in 2022/1/13 3:29 PM
 * @description：
 */
/**
 * @Title: GsonUtil.java
 * @Package com.unionpay.cqp.base.common.util
 * @author Dason
 * @date 2018年3月2日 上午10:37:52
 * @version V1.0
 */

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Type;

/**
 * @ClassName: GsonUtil
 * @Description: Gson基础类 字符串转化json及json转换对象
 * @author Dason
 * @date 2018年3月2日 上午10:37:52
 *
 */
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