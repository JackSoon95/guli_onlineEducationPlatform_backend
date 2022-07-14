package com.atguigu.edu_service.entity.excel;

import com.alibaba.excel.annotation.ExcelProperty;
import lombok.Data;

@Data
public class SubjectData {
    @ExcelProperty(index = 0)
    private String mainCat;

    @ExcelProperty(index = 1)
    private String subCat;
}
