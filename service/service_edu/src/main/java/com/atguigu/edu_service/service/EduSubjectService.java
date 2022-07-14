package com.atguigu.edu_service.service;

import com.atguigu.edu_service.entity.EduSubject;
import com.atguigu.edu_service.entity.subject.SubjectCategory;
import com.baomidou.mybatisplus.extension.service.IService;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

/**
 * <p>
 * 课程科目 服务类
 * </p>
 *
 * @author atguigu
 * @since 2022-06-30
 */
public interface EduSubjectService extends IService<EduSubject> {

    void saveSubject(MultipartFile file);

    List<SubjectCategory> listAllSubject();
}
