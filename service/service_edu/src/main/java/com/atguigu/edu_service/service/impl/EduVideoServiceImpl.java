package com.atguigu.edu_service.service.impl;

import com.atguigu.edu_service.entity.EduVideo;
import com.atguigu.edu_service.mapper.EduVideoMapper;
import com.atguigu.edu_service.service.EduVideoService;
import com.atguigu.edu_service.client.OssClient;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>
 * 课程视频 服务实现类
 * </p>
 *
 * @author atguigu
 * @since 2022-06-30
 */
@Service
public class EduVideoServiceImpl extends ServiceImpl<EduVideoMapper, EduVideo> implements EduVideoService {

    @Autowired
    private OssClient ossClient;
    @Override
    public void removeByCourseId(String id) {
        QueryWrapper<EduVideo> wrapper = new QueryWrapper<>();
        wrapper.eq("course_id", id);
        wrapper.select("video_source_id");
        List<EduVideo> list = baseMapper.selectList(wrapper);
        List<String> urls = new ArrayList<>();
        for (EduVideo video : list) {
            urls.add(video.getVideoSourceId());
        }
        System.out.println(urls);
        ossClient.deleteVideos(urls);

        QueryWrapper<EduVideo> wrapperVideo = new QueryWrapper<>();
        wrapperVideo.eq("course_id", id);
        baseMapper.delete(wrapperVideo);
    }

}
