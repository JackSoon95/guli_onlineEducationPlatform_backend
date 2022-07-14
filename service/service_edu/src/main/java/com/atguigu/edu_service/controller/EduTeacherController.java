package com.atguigu.edu_service.controller;


import com.atguigu.commonutils.R;
import com.atguigu.edu_service.entity.EduTeacher;
import com.atguigu.edu_service.entity.vo.TeacherQuery;
import com.atguigu.edu_service.service.EduTeacherService;
import com.atguigu.edu_service.service.impl.EduTeacherServiceImpl;
import com.atguigu.servicebase.exceptionHandler.GuliException;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * <p>
 * 讲师 前端控制器
 * </p>
 *
 * @author atguigu
 * @since 2022-06-27
 */

@Api(description = "讲师管理")
@RestController
@RequestMapping("/eduservice/edu-teacher")
//@CrossOrigin
public class EduTeacherController {

    @Autowired
    private EduTeacherService eduTeacherService = new EduTeacherServiceImpl();

    @ApiOperation(value = "所有讲师列表")
    @GetMapping("/findAll")
    public R findAll() {
        List<EduTeacher> list = eduTeacherService.list(null);
        return R.ok().data("items", list);
    }

    @ApiOperation(value = "根据ID删除讲师")
    @DeleteMapping("/{id}")
    public R removeTeacher(
            @ApiParam(name ="id", value ="讲师ID", required = true)
            @PathVariable String id) {
        boolean flag = eduTeacherService.removeById(id);
        if (flag) {
            return R.ok();
        } else {
            return R.error();
        }
    }

    @GetMapping("/pageTeacher/{current}/{limit}")
    public R pageListTeacher(@PathVariable long current,
                             @PathVariable long limit) {
        Page<EduTeacher> page = new Page<>(current, limit);
        eduTeacherService.page(page, null);
        long total = page.getTotal();
        List<EduTeacher> list = page.getRecords();

        return R.ok()
                .data("total", total)
                .data("rows", list);
    }

    @PostMapping("/pageTeacherCondition/{current}/{limit}")
    public R pageListTeacherCondition(@PathVariable long current,
                                      @PathVariable long limit,
                                      @RequestBody(required = false)
                                          TeacherQuery teacherQuery) {
        Page<EduTeacher> page = new Page<>(current, limit);

        QueryWrapper<EduTeacher> wrapper = new QueryWrapper<>();
        String name = teacherQuery.getName();
        Integer level = teacherQuery.getLevel();
        String begin = teacherQuery.getBegin();
        String end = teacherQuery.getEnd();

        if (!StringUtils.isEmpty(name)) {
            wrapper.like("name", name);
        }
        if (!StringUtils.isEmpty(level)) {
            wrapper.eq("level", level);
        }
        if (!StringUtils.isEmpty(begin)) {
            wrapper.ge("gmt_create", begin);
        }
        if (!StringUtils.isEmpty(end)) {
            wrapper.le("gmt_create", begin);
        }

        wrapper.orderByDesc("gmt_create");

        eduTeacherService.page(page, wrapper);
        long total = page.getTotal();
        List<EduTeacher> records = page.getRecords();

        return R.ok().data("total", total).data("rows",records);
    }

    @PostMapping("/addTeacher")
    public R addTeacher(@RequestBody EduTeacher eduTeacher) {
        boolean flag = eduTeacherService.save(eduTeacher);
        if (flag) {
            return R.ok();
        } else {
            return R.error();
        }
    }

    @GetMapping("/getTeacher/{id}")
    public R getTeacher(@PathVariable String id) {
        EduTeacher teacher = eduTeacherService.getById(id);
        return R.ok().data("teacher", teacher);
    }

    @PutMapping("/updateTeacher")
    public R updateTeacher(@RequestBody EduTeacher eduTeacher) {
        boolean flag = eduTeacherService.updateById(eduTeacher);
        if (flag) {
            return R.ok();
        } else {
            return R.error();
        }
    }
}

