package com.atguigu.edu_service.service;

import com.atguigu.edu_service.entity.EduTeacher;
import com.baomidou.mybatisplus.extension.service.IService;

import java.util.List;
import java.util.Map;

/**
 * <p>
 * 讲师 服务类
 * </p>
 *
 * @author atguigu
 * @since 2022-06-27
 */
public interface EduTeacherService extends IService<EduTeacher> {

    Map<String, Object> getPageForFront(Integer current, Integer limit);
}
