package com.atguigu.edu_service.client.fallback;

import com.atguigu.commonutils.R;
import com.atguigu.edu_service.client.OssClient;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class OssFallBack implements OssClient {
    @Override
    public R deleteVideo(String url) {
        return R.error().message("cannot delete video. fallback");
    }

    @Override
    public R deleteVideos(List<String> urls) {
        return R.error().message("cannot delete videos. fallback");
    }
}
