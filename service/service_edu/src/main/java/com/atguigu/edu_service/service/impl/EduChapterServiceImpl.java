package com.atguigu.edu_service.service.impl;

import com.atguigu.edu_service.entity.EduChapter;
import com.atguigu.edu_service.entity.EduVideo;
import com.atguigu.edu_service.entity.vo.chapter.ChapterVo;
import com.atguigu.edu_service.entity.vo.chapter.VideoVo;
import com.atguigu.edu_service.mapper.EduChapterMapper;
import com.atguigu.edu_service.service.EduChapterService;
import com.atguigu.edu_service.service.EduVideoService;
import com.atguigu.servicebase.exceptionHandler.GuliException;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>
 * 课程 服务实现类
 * </p>
 *
 * @author atguigu
 * @since 2022-06-30
 */
@Service
public class EduChapterServiceImpl extends ServiceImpl<EduChapterMapper, EduChapter> implements EduChapterService {

    @Autowired
    private EduVideoService eduVideoService;


    @Override
    public List<ChapterVo> getChapterVideoById(String id) {
        //1. get chapter list
        QueryWrapper<EduChapter> wrapperChapter = new QueryWrapper<>();
        wrapperChapter.eq("course_id", id);
        List<EduChapter> listChapter = baseMapper.selectList(wrapperChapter);

        //2. get video list
        QueryWrapper<EduVideo> wrapperVideo = new QueryWrapper<>();
        wrapperVideo.eq("course_id", id);
        List<EduVideo> listVideo = eduVideoService.list(wrapperVideo);

        List<ChapterVo> finalList = new ArrayList<>();

        //3. encap chapter
        for (int i = 0; i < listChapter.size(); i++) {
            EduChapter eduChapter = listChapter.get(i);
            ChapterVo chapterVo = new ChapterVo();
            BeanUtils.copyProperties(eduChapter, chapterVo);
            finalList.add(chapterVo);

            //4. encap video
            for (int j = 0; j < listVideo.size(); j++) {
                EduVideo eduVideo = listVideo.get(j);
                if (eduVideo.getChapterId().equals(eduChapter.getId())) {
                    VideoVo videoVo = new VideoVo();
                    BeanUtils.copyProperties(eduVideo, videoVo);
                    chapterVo.getChildren().add(videoVo);
                }
            }
        }

        return finalList;
    }

    @Override
    public boolean deleteChapterById(String id) {
        //1. check whether there is video in this chapter
        QueryWrapper<EduVideo> wrapper = new QueryWrapper<>();
        wrapper.eq("chapter_id", id);
        int count = eduVideoService.count(wrapper);

        //2. if there is, not allowed to delete
        if (count > 0) {
            throw new GuliException(20001, "please delete all videos under this chapter");
        } else {
            //3. else, delete
            int result = baseMapper.deleteById(id);
            return result > 0;
        }
    }
    @Override
    public void removeByCourseId(String id) {

        QueryWrapper<EduChapter> wrapperChapter = new QueryWrapper<>();
        wrapperChapter.eq("course_id", id);
        baseMapper.delete(wrapperChapter);
    }
}
