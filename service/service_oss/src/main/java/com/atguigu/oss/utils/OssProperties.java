package com.atguigu.oss.utils;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class OssProperties implements InitializingBean {
    @Value("${dropbox.token}")
    private String token;
    @Value("${dropbox.app}")
    private String appName;

    public static String TOKEN;
    public static String APP_NAME;

    @Override
    public void afterPropertiesSet() throws Exception {
        TOKEN = token;
        APP_NAME = appName;
    }
}
