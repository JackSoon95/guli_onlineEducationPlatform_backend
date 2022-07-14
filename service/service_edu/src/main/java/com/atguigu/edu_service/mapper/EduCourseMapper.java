package com.atguigu.edu_service.mapper;

import com.atguigu.edu_service.entity.EduCourse;
import com.atguigu.edu_service.entity.vo.CourseFinalVo;
import com.atguigu.edu_service.entity.vo.front.CourseFrontRelatedVo;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;

/**
 * <p>
 * 课程 Mapper 接口
 * </p>
 *
 * @author atguigu
 * @since 2022-06-30
 */
public interface EduCourseMapper extends BaseMapper<EduCourse> {
    public CourseFinalVo getFinalCourseResult(String id);

    public CourseFrontRelatedVo getCourseFrontInfoById(String id);

    public Integer getCourseView();

    public Integer getCourseCreated();
}
