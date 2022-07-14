package com.atguigu.demo.EasyExcelDemo;

import com.alibaba.excel.context.AnalysisContext;
import com.alibaba.excel.event.AnalysisEventListener;

import java.util.Map;

public class myEasyExcelListener extends AnalysisEventListener<DemoData> {
    private int count = 1;
    //reading row by row
    @Override
    public void invoke(DemoData demoData, AnalysisContext analysisContext) {
        System.out.println("data " + count + " - " + demoData);
        count++;
    }

    //read title (first row)
    @Override
    public void invokeHeadMap(Map<Integer, String> headMap, AnalysisContext context) {
        System.out.println("title: " + headMap);
    }

    @Override
    public void doAfterAllAnalysed(AnalysisContext analysisContext) {

    }
}
