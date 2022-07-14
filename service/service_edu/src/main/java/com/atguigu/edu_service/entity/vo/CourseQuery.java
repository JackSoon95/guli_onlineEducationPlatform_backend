package com.atguigu.edu_service.entity.vo;

import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

@Data
public class CourseQuery {
    private String title;

    private String status;

    private String begin;//注意，这里使用的是String类型，前端传过来的数据无需进行类型转换

    private String end;
}
