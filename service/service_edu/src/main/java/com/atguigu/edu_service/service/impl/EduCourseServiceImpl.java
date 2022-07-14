package com.atguigu.edu_service.service.impl;

import com.atguigu.edu_service.entity.*;
import com.atguigu.edu_service.entity.vo.CourseFinalVo;
import com.atguigu.edu_service.entity.vo.front.CourseFrontFilterVo;
import com.atguigu.edu_service.entity.vo.CourseInfoVo;
import com.atguigu.edu_service.entity.vo.front.CourseFrontRelatedVo;
import com.atguigu.edu_service.mapper.EduCourseMapper;
import com.atguigu.edu_service.service.EduChapterService;
import com.atguigu.edu_service.service.EduCourseDescriptionService;
import com.atguigu.edu_service.service.EduCourseService;
import com.atguigu.edu_service.service.EduVideoService;
import com.atguigu.servicebase.exceptionHandler.GuliException;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * <p>
 * 课程 服务实现类
 * </p>
 *
 * @author atguigu
 * @since 2022-06-30
 */
@Service
public class EduCourseServiceImpl extends ServiceImpl<EduCourseMapper, EduCourse> implements EduCourseService {

    @Autowired
    private EduCourseDescriptionService eduCourseDescriptionService;
    @Autowired
    private EduChapterService eduChapterService;
    @Autowired
    private EduVideoService eduVideoService;

    @Override
    public String  saveCourse(CourseInfoVo courseInfoVo) {
        EduCourse eduCourse = new EduCourse();
        BeanUtils.copyProperties(courseInfoVo, eduCourse);
        boolean result = this.save(eduCourse);

        if (!result) {
            throw new GuliException(20001, "save failed");
        }

        String id = eduCourse.getId();

        EduCourseDescription eduCourseDescription = new EduCourseDescription();
        eduCourseDescription.setDescription(courseInfoVo.getDescription());
        eduCourseDescription.setId(id);
        eduCourseDescriptionService.save(eduCourseDescription);

        return id;
    }

    @Override
    public CourseInfoVo getCourseInfoById(String id) {
        //1. get course
        EduCourse eduCourse = baseMapper.selectById(id);
        CourseInfoVo courseInfoVo = new CourseInfoVo();
        BeanUtils.copyProperties(eduCourse, courseInfoVo);

        //2. get description
        EduCourseDescription eduCourseDescription = eduCourseDescriptionService.getById(id);
        if (eduCourseDescription != null) {
            courseInfoVo.setDescription(eduCourseDescription.getDescription());
        } else {
            courseInfoVo.setDescription("");
        }
        return courseInfoVo;
    }

    @Override
    public void updateCourse(CourseInfoVo courseInfoVo) {
        EduCourse eduCourse = new EduCourse();
        BeanUtils.copyProperties(courseInfoVo, eduCourse);
        int result = baseMapper.updateById(eduCourse);

        if (result <= 0) {
            throw new GuliException(20001, "save failed");
        }

        String id = eduCourse.getId();
        EduCourseDescription eduCourseDescription = new EduCourseDescription();
        eduCourseDescription.setDescription(courseInfoVo.getDescription());
        eduCourseDescription.setId(id);
        eduCourseDescriptionService.updateById(eduCourseDescription);
    }

    @Override
    public CourseFinalVo getFinalCourseInfoById(String id) {
        CourseFinalVo finalCourseResult = baseMapper.getFinalCourseResult(id);
        return finalCourseResult;
    }

    @Override
    public void removeByIdRecursively(String id) {
        //video
        eduVideoService.removeByCourseId(id);

        //chapter
        eduChapterService.removeByCourseId(id);

        //description
        eduCourseDescriptionService.removeById(id);

        //course
        baseMapper.deleteById(id);
    }

    @Override
    public List<EduCourse> getCourseInfoByTeacherId(String id) {
        QueryWrapper<EduCourse> wrapper = new QueryWrapper<>();
        wrapper.eq("teacher_id", id);
        List<EduCourse> courses = baseMapper.selectList(wrapper);

        return courses;
    }

    @Override
    public Map<String, Object> getPageForFront(Integer current, Integer limit, CourseFrontFilterVo vo) {

        Page<EduCourse> page = new Page<>(current, limit);

        String subjectCatId = vo.getSubjectCatId();
        String subjectId = vo.getSubjectId();
        String buyCountSort = vo.getBuyCountSort();
        String gmtCreateSort = vo.getGmtCreateSort();
        String priceSort = vo.getPriceSort();

        QueryWrapper<EduCourse> wrapper = new QueryWrapper<>();

        if (!StringUtils.isEmpty(subjectCatId)) {
            wrapper.eq("subject_parent_id", subjectCatId);
        }

        if (!StringUtils.isEmpty(subjectId)) {
            wrapper.eq("subject_id", subjectId);
        }

        if (!StringUtils.isEmpty(buyCountSort)) {
            wrapper.orderByDesc("buy_count");
        }

        if (!StringUtils.isEmpty(gmtCreateSort)) {
            wrapper.orderByDesc("gmt_create");
        }

        if (!StringUtils.isEmpty(priceSort)) {
            wrapper.orderByDesc("price");
        }
        baseMapper.selectPage(page, wrapper);

        List<EduCourse> courses = page.getRecords();
        long pageCurrent = page.getCurrent();
        long pageSize =  page.getSize();
        long pageNumber = page.getPages();
        long courseTotal = page.getTotal();
        boolean hasPrevious = page.hasPrevious();
        boolean hasNext = page.hasNext();

        HashMap<String, Object> map = new HashMap<>();
        map.put("list", courses);
        map.put("current", pageCurrent);
        map.put("size", pageSize);
        map.put("pageTotal", pageNumber);
        map.put("courseTotal", courseTotal);
        map.put("hasPrevious", hasPrevious);
        map.put("hasNext", hasNext);

        return map;
    }

    @Override
    public CourseFrontRelatedVo getCourseFrontInfoById(String id) {
        CourseFrontRelatedVo vo = baseMapper.getCourseFrontInfoById(id);
        return vo;
    }

    @Override
    public Map<String, Object> getCount() {
        Integer courseView = baseMapper.getCourseView();
        Integer courseCreated = baseMapper.getCourseCreated();
        Map<String, Object> map = new HashMap<>();
        map.put("courseView", courseView);
        map.put("courseCreated", courseCreated);
        return map;
    }

}
