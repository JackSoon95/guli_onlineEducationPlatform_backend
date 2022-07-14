package com.atguigu.oss.service;

import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface OssService {
    String uploadCover(MultipartFile file);
    String uploadVideo(MultipartFile file);

    void removeVideo(String url);
    void removeBatchVideo(List<String> urls);
}
