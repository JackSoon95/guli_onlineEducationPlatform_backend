package com.atguigu.edu_service.entity.subject;

import lombok.Data;

import java.util.List;


@Data
public class SubjectCategory {
    private String id;
    private String title;
    private List<Subject> children;
}
