package com.atguigu.edu_service.entity.vo.chapter;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class ChapterVo {
    private String id;
    private String title;
    private List<VideoVo> children = new ArrayList<>();
}
