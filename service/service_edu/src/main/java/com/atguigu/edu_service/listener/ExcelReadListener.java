package com.atguigu.edu_service.listener;

import com.alibaba.excel.context.AnalysisContext;
import com.alibaba.excel.event.AnalysisEventListener;
import com.atguigu.edu_service.entity.EduSubject;
import com.atguigu.edu_service.entity.excel.SubjectData;
import com.atguigu.edu_service.service.EduSubjectService;
import com.atguigu.edu_service.service.EduTeacherService;
import com.atguigu.servicebase.exceptionHandler.GuliException;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;

import java.util.Map;

public class ExcelReadListener extends AnalysisEventListener<SubjectData> {

    private EduSubjectService eduSubjectService;

    public ExcelReadListener() {
    }

    public ExcelReadListener(EduSubjectService eduSubjectService) {
        this.eduSubjectService = eduSubjectService;
    }

    @Override
    public void invoke(SubjectData subjectData, AnalysisContext analysisContext) {
        if (subjectData == null) {
            throw new GuliException(20001, "Excel 数据不能为空");
        }

        EduSubject mainCategory = existMainCategory(subjectData.getMainCat());
        if (mainCategory == null) {
            mainCategory = new EduSubject();
            mainCategory.setParentId("0");
            mainCategory.setTitle(subjectData.getMainCat());
            eduSubjectService.save(mainCategory);
        }

        String parentId = mainCategory.getId();

        EduSubject subCategory = existSubCategory(subjectData.getSubCat(), parentId);
        if (subCategory == null) {
            subCategory = new EduSubject();
            subCategory.setParentId(parentId);
            subCategory.setTitle(subjectData.getSubCat());
            eduSubjectService.save(subCategory);
        }
    }

    @Override
    public void invokeHeadMap(Map<Integer, String> headMap, AnalysisContext context) {

    }

    @Override
    public void doAfterAllAnalysed(AnalysisContext analysisContext) {

    }

    private EduSubject existMainCategory(String name) {
        QueryWrapper<EduSubject> wrapper = new QueryWrapper<>();
        wrapper.eq("title", name);
        wrapper.eq("parent_id", "0");

        return eduSubjectService.getOne(wrapper);
    }

    private EduSubject existSubCategory(String name, String parentId) {
        QueryWrapper<EduSubject> wrapper = new QueryWrapper<>();
        wrapper.eq("title", name);
        wrapper.eq("parent_id", parentId);

        return eduSubjectService.getOne(wrapper);
    }
}
