package com.atguigu.demo.EasyExcelDemo;

import com.alibaba.excel.EasyExcel;

import java.util.ArrayList;
import java.util.List;

public class EasyExcelTestWrite {
    public static void main(String[] args) {
        String filePath = "E:\\student.xlsx";

        EasyExcel.write(filePath, DemoData.class).sheet("students").doWrite(list());
    }

    public static List<DemoData> list() {
        ArrayList<DemoData> list = new ArrayList<>();

        for (int i = 0; i < 10; i++) {
            list.add(new DemoData(i,"Lucy" + i));
        }

        return list;
    }
}
