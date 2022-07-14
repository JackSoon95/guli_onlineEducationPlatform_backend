package com.atguigu.cms.controller;


import com.atguigu.cms.entity.Banner;
import com.atguigu.cms.service.BannerService;
import com.atguigu.commonutils.R;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

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
@RequestMapping("/cms/admin/banner")
//@CrossOrigin
public class BannerAdminController {
    @Autowired
    private BannerService bannerService;

    @GetMapping("/page/{current}/{limit}")
    public R getPagination(@PathVariable Integer current,
                           @PathVariable Integer limit) {
        Page<Banner> page = new Page<>(current, limit);
        bannerService.page(page, null);
        List<Banner> records = page.getRecords();
        long total = page.getTotal();

        return R.ok().data("list", records).data("total", total);
    }

    @GetMapping("/{id}")
    public R getById(@PathVariable String  id) {
        Banner banner = bannerService.getById(id);
        return R.ok().data("banner", banner);
    }

    @PostMapping("")
    public R addBanner(@RequestBody Banner banner) {
        bannerService.save(banner);
        return R.ok();
    }

    @PutMapping("")
    public R updateBanner(@RequestBody Banner banner) {
        bannerService.updateById(banner);
        return R.ok();
    }

    @DeleteMapping("/{id}")
    public R deleteById(@PathVariable String id) {
        bannerService.removeById(id);
        //to do oos
        return R.ok();
    }

}

