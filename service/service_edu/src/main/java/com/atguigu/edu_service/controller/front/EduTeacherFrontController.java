package com.atguigu.edu_service.controller.front;


import com.atguigu.commonutils.R;
import com.atguigu.edu_service.entity.EduCourse;
import com.atguigu.edu_service.entity.EduTeacher;
import com.atguigu.edu_service.service.EduCourseService;
import com.atguigu.edu_service.service.EduTeacherService;
import io.swagger.models.auth.In;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/eduservice/teacherFront")
//@CrossOrigin
public class EduTeacherFrontController {
    @Autowired
    private EduTeacherService eduTeacherService;
    @Autowired
    private EduCourseService eduCourseService;

    @GetMapping("/page/{current}/{limit}")
    public R getPage(@PathVariable Integer current, @PathVariable Integer limit) {
        Map<String, Object> map = eduTeacherService.getPageForFront(current, limit);
        return R.ok().data(map);
    }

    @GetMapping("/{id}")
    public R getTeacherInfoById(@PathVariable String id) {
        EduTeacher teacher = eduTeacherService.getById(id);
        List<EduCourse> course = eduCourseService.getCourseInfoByTeacherId(id);
        return R.ok().data("teacher", teacher).data("courses",course);
    }


}
