package com.atguigu.oss.service.impl;

import com.atguigu.oss.service.OssService;
import com.atguigu.oss.utils.OssProperties;
import com.atguigu.servicebase.exceptionHandler.GuliException;
import com.dropbox.core.DbxRequestConfig;
import com.dropbox.core.v2.DbxClientV2;
import com.dropbox.core.v2.files.DeleteArg;
import com.dropbox.core.v2.files.DeleteResult;
import com.dropbox.core.v2.files.FileMetadata;
import com.dropbox.core.v2.files.Metadata;
import org.joda.time.DateTime;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
public class OssServiceImpl implements OssService {
    @Override
    public String uploadCover(MultipartFile file) {
        String filename = file.getOriginalFilename();
        filename = UUID.randomUUID().toString().replaceAll("-","") + filename;

        String dateString = new DateTime().toString("yyyy/MM/dd/");
        String path = "/cover/" + dateString;
        return uploadDropbox(file, filename, path);
    }

    @Override
    public String uploadVideo(MultipartFile file) {
        return uploadDropbox(file, file.getOriginalFilename(), "/video/");
    }

    @Override
    public void removeVideo(String url) {
        delete(videoUrlToPath(url));
    }

    @Override
    public void removeBatchVideo(List<String> urls) {
        List<DeleteArg> list = new ArrayList<>();
        for (String url : urls) {
            String path = videoUrlToPath(url);
            list.add(new DeleteArg(path));
        }

        delete(list);
    }

    private String videoUrlToPath(String url) {

        String filename = url.substring(url.lastIndexOf('/'), url.lastIndexOf('?'));
        filename = "/video" + filename;

        return filename;
    }

    private void delete(String filename) {
        String token = OssProperties.TOKEN;
        String appName = OssProperties.APP_NAME;

        DbxRequestConfig config = DbxRequestConfig.newBuilder(appName)
                .withUserLocale("en_US")
                .build();

        DbxClientV2 client = new DbxClientV2(config, token);

        try {
            client.files().deleteV2(filename);
        } catch (Exception e) {
            throw new GuliException(20001, "failed to delete file");
        }
    }

    private void delete(List<DeleteArg> list) {
        System.out.println("entered deleteVideos");
        String token = OssProperties.TOKEN;
        String appName = OssProperties.APP_NAME;

        DbxRequestConfig config = DbxRequestConfig.newBuilder(appName)
                .withUserLocale("en_US")
                .build();

        DbxClientV2 client = new DbxClientV2(config, token);

        try {
            client.files().deleteBatch(list);
        } catch (Exception e) {
            throw new GuliException(20001, "failed to delete files");
        }
    }

    private String uploadDropbox(MultipartFile file, String filename, String path) {
        String token = OssProperties.TOKEN;
        String appName = OssProperties.APP_NAME;

        DbxRequestConfig config = DbxRequestConfig.newBuilder(appName)
                .withUserLocale("en_US")
                .build();

        DbxClientV2 client = new DbxClientV2(config, token);

        InputStream in = null;
        String url = null;

        try {
            in = file.getInputStream();
            FileMetadata metadata = client.files().uploadBuilder(path + filename)
                    .uploadAndFinish(in);
            url = client.sharing().createSharedLinkWithSettings(path + filename).getUrl().replace("?dl=0", "?raw=1");
        } catch (Exception e) {
            throw new GuliException(20001, "failed to upload file, please rename");
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return url;
    }


}
