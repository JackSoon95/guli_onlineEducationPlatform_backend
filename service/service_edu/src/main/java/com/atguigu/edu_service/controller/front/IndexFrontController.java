package com.atguigu.edu_service.controller.front;

import com.atguigu.commonutils.R;
import com.atguigu.edu_service.entity.EduCourse;
import com.atguigu.edu_service.entity.EduTeacher;
import com.atguigu.edu_service.service.EduCourseService;
import com.atguigu.edu_service.service.EduTeacherService;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/eduservice/indexFront")
//@CrossOrigin
public class IndexFrontController {
    @Autowired
    private EduTeacherService eduTeacherService;
    @Autowired
    private EduCourseService eduCourseService;

    @GetMapping("/index")
    @Cacheable(value = "teacherAndCourse", key = "'selectIndexList'")
    public R getTeachers() {
        QueryWrapper<EduCourse> wrapperCourse = new QueryWrapper<>();
        wrapperCourse.orderByDesc("id");
        wrapperCourse.last("limit 8");
        List<EduCourse> courses = eduCourseService.list(wrapperCourse);

        QueryWrapper<EduTeacher> wrapperTeacher = new QueryWrapper<>();
        wrapperTeacher.orderByDesc("id");
        wrapperTeacher.last("limit 4");
        List<EduTeacher> teachers = eduTeacherService.list(wrapperTeacher);

        return R.ok().data("teacherList", teachers).data("courseList", courses);
    }
}
