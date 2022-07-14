package com.atguigu.edu_service.client;

import com.atguigu.commonutils.R;
import com.atguigu.edu_service.client.fallback.OssFallBack;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@FeignClient(name = "service-oss", fallback = OssFallBack.class)
@Component
public interface OssClient {

    @DeleteMapping("/eduoss/fileoss")
    public R deleteVideo(@RequestParam String url);

    @DeleteMapping("/eduoss/fileoss/videos")
    public R deleteVideos(@RequestParam("urls") List<String> urls);
}
