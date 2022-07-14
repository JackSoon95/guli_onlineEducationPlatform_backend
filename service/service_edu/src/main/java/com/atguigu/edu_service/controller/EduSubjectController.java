package com.atguigu.edu_service.controller;


import com.atguigu.commonutils.R;
import com.atguigu.edu_service.entity.subject.SubjectCategory;
import com.atguigu.edu_service.service.EduSubjectService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import org.springframework.web.multipart.MultipartFile;

import java.util.List;

/**
 * <p>
 * 课程科目 前端控制器
 * </p>
 *
 * @author atguigu
 * @since 2022-06-30
 */

@RestController
@RequestMapping("/eduservice/subject")
//@CrossOrigin
public class EduSubjectController {

    @Autowired
    private EduSubjectService eduSubjectService;

    @PostMapping("/addSubject")
    public R addSubject(MultipartFile file) {
        eduSubjectService.saveSubject(file);
        return R.ok();
    }

    @GetMapping("/listSubject")
    public R listSubject() {
        List<SubjectCategory> list = eduSubjectService.listAllSubject();
        return R.ok().data("list", list);
    }
}

