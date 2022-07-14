package com.atguigu.demo.EasyExcelDemo;

import com.alibaba.excel.EasyExcel;

public class EasyExcelTestRead {
    public static void main(String[] args) {
        String filePath = "E:\\student.xlsx";

        EasyExcel.read(filePath, DemoData.class, new myEasyExcelListener()).sheet().doRead();
    }
}
