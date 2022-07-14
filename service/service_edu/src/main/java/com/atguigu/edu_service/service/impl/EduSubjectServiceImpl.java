package com.atguigu.edu_service.service.impl;

import com.alibaba.excel.EasyExcel;
import com.atguigu.edu_service.entity.EduSubject;
import com.atguigu.edu_service.entity.excel.SubjectData;
import com.atguigu.edu_service.entity.subject.Subject;
import com.atguigu.edu_service.entity.subject.SubjectCategory;
import com.atguigu.edu_service.listener.ExcelReadListener;
import com.atguigu.edu_service.mapper.EduSubjectMapper;
import com.atguigu.edu_service.mapper.EduTeacherMapper;
import com.atguigu.edu_service.service.EduSubjectService;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>
 * 课程科目 服务实现类
 * </p>
 *
 * @author atguigu
 * @since 2022-06-30
 */
@Service
public class EduSubjectServiceImpl extends ServiceImpl<EduSubjectMapper, EduSubject> implements EduSubjectService {
    @Override
    public void saveSubject(MultipartFile file) {
        try {
            InputStream in = file.getInputStream();
            EasyExcel.read(in, SubjectData.class, new ExcelReadListener(this)).sheet().doRead();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    @Override
    public List<SubjectCategory> listAllSubject() {
        //1. find subject categories
        QueryWrapper<EduSubject> wrapperForCat = new QueryWrapper<>();
        wrapperForCat.eq("parent_id", "0");
        List<EduSubject> subjectCategories = baseMapper.selectList(wrapperForCat);

        //2. find subjects
        QueryWrapper<EduSubject> wrapperForSubjects = new QueryWrapper<>();
        wrapperForSubjects.ne("parent_id", "0");
        List<EduSubject> subjects = baseMapper.selectList(wrapperForSubjects);

        //3. put into the final list
        List<SubjectCategory> finalList = new ArrayList<>();
        for (int i = 0; i < subjectCategories.size(); i++) {
            //3.1 prepare subject category
            EduSubject category = subjectCategories.get(i);
            //String id = eduSubject.getId();
            //String title = eduSubject.getTitle();

            SubjectCategory subjectCategory = new SubjectCategory();
            //subjectCategory.setId(id);
            //subjectCategory.setTitle(title);
            BeanUtils.copyProperties(category, subjectCategory);

            finalList.add(subjectCategory);

            //4. create list and put in the second layer
            List<Subject> subjectsFinalList = new ArrayList<>();

            for (int j = 0; j < subjects.size(); j++) {
                //3.2 prepare subjects to put into category
                EduSubject eduSubject = subjects.get(j);
                if (eduSubject.getParentId().equals(category.getId())) {
                    Subject subject = new Subject();
                    BeanUtils.copyProperties(eduSubject, subject);
                    subjectsFinalList.add(subject);
                }
            }

            subjectCategory.setChildren(subjectsFinalList);
        }

        return finalList;
    }
}
