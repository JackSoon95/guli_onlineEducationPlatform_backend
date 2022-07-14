package com.atguigu.edu_service.service;

import com.atguigu.edu_service.entity.EduComment;
import com.baomidou.mybatisplus.extension.service.IService;

import java.util.List;
import java.util.Map;

/**
 * <p>
 * 评论 服务类
 * </p>
 *
 * @author atguigu
 * @since 2022-07-10
 */
public interface EduCommentService extends IService<EduComment> {

    Map<String, Object> getListByCourseId(Integer current, Integer limit, String courseId);
}
