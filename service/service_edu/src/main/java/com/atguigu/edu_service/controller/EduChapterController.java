package com.atguigu.edu_service.controller;


import com.atguigu.commonutils.R;
import com.atguigu.edu_service.entity.EduChapter;
import com.atguigu.edu_service.entity.vo.chapter.ChapterVo;
import com.atguigu.edu_service.service.EduChapterService;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * <p>
 * 课程 前端控制器
 * </p>
 *
 * @author atguigu
 * @since 2022-06-30
 */
@RestController
@RequestMapping("/eduservice/chapter")
//@CrossOrigin
public class EduChapterController {

    @Autowired
    private EduChapterService eduChapterService;

    @GetMapping("/getChapterVideo/{id}")
    public R getChapterVideoById(@PathVariable String id) {
        List<ChapterVo> list = eduChapterService.getChapterVideoById(id);
        return R.ok().data("list", list);
    }

    @PostMapping("/addChapter")
    public R addChapter(@RequestBody EduChapter eduChapter) {
        eduChapterService.save(eduChapter);
        return R.ok();
    }

    @GetMapping("/getChapter/{id}")
    public R getChapterById(@PathVariable String id) {
        EduChapter chapter = eduChapterService.getById(id);
        return R.ok().data("chapter", chapter);
    }

    @PutMapping("/updateChapter")
    public R updateChapter(@RequestBody EduChapter eduChapter) {
        eduChapterService.updateById(eduChapter);
        return R.ok();
    }

    @DeleteMapping("/{id}")
    public R deleteChapterById(@PathVariable String id) {
        if (eduChapterService.deleteChapterById(id)) {
            return R.ok();
        } else {
            return R.error();
        }
    }

    @DeleteMapping("/deleteCourse/{courseId}")
    public R deleteChapterByCourseId(@PathVariable String courseId) {
        eduChapterService.removeByCourseId(courseId);
        return R.ok();
    }


}

