package com.atguigu.oss.controller;

import com.atguigu.commonutils.R;
import com.atguigu.oss.service.OssService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/eduoss/fileoss")
//@CrossOrigin
public class OssController {
    @Autowired
    private OssService ossService;

    @PostMapping("/cover")
    public R uploadOssCover(MultipartFile file) {
        String url = ossService.uploadCover(file);
        return R.ok().data("url", url);
    }

    @PostMapping("/video")
    public R uploadOssVideo(MultipartFile file) {
        String url = ossService.uploadVideo(file);
        return R.ok().data("url", url);
    }

    @DeleteMapping("")
    public R deleteVideo(@RequestParam String url) {
        ossService.removeVideo(url);
        return R.ok();
    }

    @DeleteMapping("/videos")
    public R deleteVideos(@RequestParam("urls") List<String> urls) {
        ossService.removeBatchVideo(urls);
        return R.ok();
    }
}
