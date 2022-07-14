package com.atguigu.edu_service.controller;


import com.atguigu.commonutils.R;
import com.atguigu.edu_service.entity.EduVideo;
import com.atguigu.edu_service.service.EduVideoService;
import com.atguigu.edu_service.client.OssClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

/**
 * <p>
 * 课程视频 前端控制器
 * </p>
 *
 * @author atguigu
 * @since 2022-06-30
 */
@RestController
@RequestMapping("/eduservice/video")
//@CrossOrigin
public class EduVideoController {
    @Autowired
    private EduVideoService eduVideoService;

    @Autowired
    private OssClient ossClient;

    @PostMapping("/addVideo")
    public R addVideo(@RequestBody EduVideo video) {
        System.out.println(video.getVideoSourceId());
        System.out.println(video.getVideoOriginalName());
        eduVideoService.save(video);
        return R.ok();
    }

    @GetMapping("/getVideo/{id}")
    public R getVideoById(@PathVariable String id) {
        EduVideo video = eduVideoService.getById(id);
        return R.ok().data("video", video);
    }

    @PutMapping("/updateVideo")
    public R updateVideo(@RequestBody EduVideo video) {
        eduVideoService.updateById(video);
        return R.ok();
    }

    @DeleteMapping("/{id}")
    public R deleteVideoById(@PathVariable String id) {

        EduVideo video = eduVideoService.getById(id);
        String url = video.getVideoSourceId();

        if (!StringUtils.isEmpty(url)) {
            R result = ossClient.deleteVideo(url);
            if (result.getCode() == 20001) {
                System.out.println("Hystrix worked");
            }
        }

        eduVideoService.removeById(id);
        return R.ok();
    }
}

