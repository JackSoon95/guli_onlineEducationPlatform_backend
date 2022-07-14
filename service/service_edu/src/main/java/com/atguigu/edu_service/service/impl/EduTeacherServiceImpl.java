package com.atguigu.edu_service.service.impl;

import com.atguigu.edu_service.entity.EduTeacher;
import com.atguigu.edu_service.mapper.EduTeacherMapper;
import com.atguigu.edu_service.service.EduTeacherService;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import io.swagger.models.auth.In;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * <p>
 * 讲师 服务实现类
 * </p>
 *
 * @author atguigu
 * @since 2022-06-27
 */
@Service
public class EduTeacherServiceImpl extends ServiceImpl<EduTeacherMapper, EduTeacher> implements EduTeacherService {

    @Override
    public Map<String, Object> getPageForFront(Integer current, Integer limit) {
        Page<EduTeacher> page = new Page<>(current, limit);

        QueryWrapper<EduTeacher> wrapper = new QueryWrapper<>();
        wrapper.orderByDesc("id");
        baseMapper.selectPage(page, wrapper);

        List<EduTeacher> teachers = page.getRecords();
        long pageCurrent = page.getCurrent();
        long pageSize =  page.getSize();
        long pageNumber = page.getPages();
        long teacherTotal = page.getTotal();
        boolean hasPrevious = page.hasPrevious();
        boolean hasNext = page.hasNext();

        HashMap<String, Object> map = new HashMap<>();
        map.put("list", teachers);
        map.put("current", pageCurrent);
        map.put("size", pageSize);
        map.put("pageTotal", pageNumber);
        map.put("teacherTotal", teacherTotal);
        map.put("hasPrevious", hasPrevious);
        map.put("hasNext", hasNext);

        return map;
    }
}
