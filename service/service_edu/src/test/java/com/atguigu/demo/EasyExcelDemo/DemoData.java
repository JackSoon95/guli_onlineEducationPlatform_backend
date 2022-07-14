package com.atguigu.demo.EasyExcelDemo;

import com.alibaba.excel.annotation.ExcelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class DemoData {
    @ExcelProperty(value = "Student Id")
    private Integer id;

    @ExcelProperty(value = "Student name")
    private String name;
}
