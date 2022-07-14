package com.atguigu.edu_service.service.impl;

import com.atguigu.edu_service.entity.EduComment;
import com.atguigu.edu_service.entity.EduTeacher;
import com.atguigu.edu_service.mapper.EduCommentMapper;
import com.atguigu.edu_service.service.EduCommentService;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * <p>
 * 评论 服务实现类
 * </p>
 *
 * @author atguigu
 * @since 2022-07-10
 */
@Service
public class EduCommentServiceImpl extends ServiceImpl<EduCommentMapper, EduComment> implements EduCommentService {

    @Override
    public Map<String, Object> getListByCourseId(Integer current, Integer limit, String courseId) {
        Page<EduComment> page = new Page<>(current, limit);

        QueryWrapper<EduComment> wrapper = new QueryWrapper<>();
        wrapper.eq("course_id",courseId);
        wrapper.orderByDesc("gmt_create");
        baseMapper.selectPage(page, wrapper);


        List<EduComment> comments = page.getRecords();
        long pageCurrent = page.getCurrent();
        long pageSize =  page.getSize();
        long pageNumber = page.getPages();
        long commentTotal = page.getTotal();
        boolean hasPrevious = page.hasPrevious();
        boolean hasNext = page.hasNext();

        HashMap<String, Object> map = new HashMap<>();
        map.put("list", comments);
        map.put("current", pageCurrent);
        map.put("size", pageSize);
        map.put("pageTotal", pageNumber);
        map.put("commentTotal", commentTotal);
        map.put("hasPrevious", hasPrevious);
        map.put("hasNext", hasNext);

        return map;
    }
}
