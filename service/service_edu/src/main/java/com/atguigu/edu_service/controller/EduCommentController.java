package com.atguigu.edu_service.controller;


import com.atguigu.commonutils.R;
import com.atguigu.edu_service.entity.EduComment;
import com.atguigu.edu_service.service.EduCommentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * <p>
 * 评论 前端控制器
 * </p>
 *
 * @author atguigu
 * @since 2022-07-10
 */
@RestController
@RequestMapping("/eduservice/comment")
//@CrossOrigin
public class EduCommentController {

    @Autowired
    private EduCommentService eduCommentService;

    @PostMapping
    public R newComment(@RequestBody EduComment eduComment) {
        boolean save = eduCommentService.save(eduComment);
        if (save) {
            return R.ok();
        } else {
            return R.error();
        }
    }

    @GetMapping("/{current}/{limit}/{courseId}")
    public R getPageCommentsByCourseId(@PathVariable Integer current,
                                       @PathVariable Integer limit,
                                       @PathVariable String courseId) {
        Map<String, Object> page = eduCommentService.getListByCourseId(current, limit, courseId);
        return R.ok().data(page);
    }
}

