package com.atguigu.edu_service.controller;


import com.atguigu.commonutils.R;
import com.atguigu.edu_service.entity.EduCourse;
import com.atguigu.edu_service.entity.EduTeacher;
import com.atguigu.edu_service.entity.vo.CourseFinalVo;
import com.atguigu.edu_service.entity.vo.CourseInfoVo;
import com.atguigu.edu_service.entity.vo.CourseQuery;
import com.atguigu.edu_service.entity.vo.TeacherQuery;
import com.atguigu.edu_service.service.EduCourseService;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * <p>
 * 课程 前端控制器
 * </p>
 *
 * @author atguigu
 * @since 2022-06-30
 */
@RestController
@RequestMapping("/eduservice/course")
//@CrossOrigin
public class EduCourseController {
    @Autowired
    private EduCourseService eduCourseService;

    @PostMapping("/saveCourse")
    public R addCourse(@RequestBody CourseInfoVo courseInfoVo) {
        String id = eduCourseService.saveCourse(courseInfoVo);
        return R.ok().data("id", id);
    }

    @GetMapping("/getCourse/{id}")
    public R getCourse(@PathVariable String id) {
        CourseInfoVo course = eduCourseService.getCourseInfoById(id);
        return R.ok().data("course", course);
    }

    @PutMapping("/updateCourse")
    public R updateCourse(@RequestBody CourseInfoVo courseInfoVo) {
        eduCourseService.updateCourse(courseInfoVo);
        return R.ok();
    }

    @GetMapping("/getFinalCourseInfo/{id}")
    public R getFinalCourseInfo(@PathVariable String id) {
        CourseFinalVo result = eduCourseService.getFinalCourseInfoById(id);
        return R.ok().data("courseInfo", result);
    }

    @PutMapping("/updateStatus/{id}")
    public R updateStatus(@PathVariable String id) {
        EduCourse eduCourse = new EduCourse();
        eduCourse.setId(id);
        eduCourse.setStatus("Normal");
        eduCourseService.updateById(eduCourse);
        return R.ok();
    }

    @PostMapping("/pageCourseCondition/{current}/{limit}")
    public R pageListCourseCondition(@PathVariable long current,
                                      @PathVariable long limit,
                                      @RequestBody(required = false)
                                     CourseQuery courseQuery) {
        Page<EduCourse> page = new Page<>(current, limit);

        QueryWrapper<EduCourse> wrapper = new QueryWrapper<>();

        String title = courseQuery.getTitle();
        String status = courseQuery.getStatus();
        String begin = courseQuery.getBegin();
        String end = courseQuery.getEnd();

        if (!StringUtils.isEmpty(title)) {
            wrapper.like("title", title);
        }
        if (!StringUtils.isEmpty(status)) {
            wrapper.eq("status", status);
        }
        if (!StringUtils.isEmpty(begin)) {
            wrapper.ge("gmt_create", begin);
        }
        if (!StringUtils.isEmpty(end)) {
            wrapper.le("gmt_create", begin);
        }

        wrapper.orderByDesc("gmt_create");

        eduCourseService.page(page, wrapper);
        long total = page.getTotal();
        List<EduCourse> records = page.getRecords();

        return R.ok().data("total", total).data("rows",records);
    }

    @DeleteMapping("/{id}")
    public R deleteCourseById(@PathVariable String id) {
        eduCourseService.removeByIdRecursively(id);
        return R.ok();
    }

    @GetMapping("/count")
    public R getCount() {

        Map<String, Object> map = eduCourseService.getCount();

        return R.ok().data(map);
    }
}

