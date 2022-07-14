package com.atguigu.edu_service.service;

import com.atguigu.edu_service.entity.EduCourse;
import com.atguigu.edu_service.entity.vo.CourseFinalVo;
import com.atguigu.edu_service.entity.vo.front.CourseFrontFilterVo;
import com.atguigu.edu_service.entity.vo.CourseInfoVo;
import com.atguigu.edu_service.entity.vo.front.CourseFrontRelatedVo;
import com.baomidou.mybatisplus.extension.service.IService;

import java.util.List;
import java.util.Map;

/**
 * <p>
 * 课程 服务类
 * </p>
 *
 * @author atguigu
 * @since 2022-06-30
 */
public interface EduCourseService extends IService<EduCourse> {

    String saveCourse(CourseInfoVo courseInfoVo);

    CourseInfoVo getCourseInfoById(String id);

    void updateCourse(CourseInfoVo courseInfoVo);

    CourseFinalVo getFinalCourseInfoById(String id);

    void removeByIdRecursively(String id);

    List<EduCourse> getCourseInfoByTeacherId(String id);

    Map<String, Object> getPageForFront(Integer current, Integer limit, CourseFrontFilterVo vo);

    CourseFrontRelatedVo getCourseFrontInfoById(String id);

    Map<String, Object> getCount();
}
