package com.atguigu.edu_service.entity.vo;

import lombok.Data;
import lombok.ToString;

import java.io.Serializable;

@Data
@ToString
public class CourseFinalVo  {
    private String id;
    private String title;
    private String cover;
    private Integer lessonNum;
    private String subjectCategory;
    private String subject;
    private String teacherName;
    private String price;//只用于显示
}
