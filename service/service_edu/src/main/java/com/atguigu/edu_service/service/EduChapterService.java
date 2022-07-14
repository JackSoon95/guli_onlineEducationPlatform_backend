package com.atguigu.edu_service.service;

import com.atguigu.edu_service.entity.EduChapter;
import com.atguigu.edu_service.entity.vo.chapter.ChapterVo;
import com.baomidou.mybatisplus.extension.service.IService;

import java.util.List;

/**
 * <p>
 * 课程 服务类
 * </p>
 *
 * @author atguigu
 * @since 2022-06-30
 */
public interface EduChapterService extends IService<EduChapter> {

    List<ChapterVo> getChapterVideoById(String id);

    boolean deleteChapterById(String id);

    void removeByCourseId(String id);
}
