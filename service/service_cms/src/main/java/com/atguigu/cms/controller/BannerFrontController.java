package com.atguigu.cms.controller;


import com.atguigu.cms.entity.Banner;
import com.atguigu.cms.service.BannerService;
import com.atguigu.commonutils.R;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * <p>
 * 首页banner表 前端控制器
 * </p>
 *
 * @author atguigu
 * @since 2022-07-05
 */
@RestController
@RequestMapping("/cms/banner")
//@CrossOrigin
public class BannerFrontController {

    @Autowired
    private BannerService bannerService;

    @GetMapping
    public R getAll() {
        List<Banner> list = bannerService.selectAll();
        return R.ok().data("bannerList", list);
    }
}

