package com.atguigu.cms.controller;


import com.atguigu.cms.service.StatisticsDailyService;
import com.atguigu.commonutils.R;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * <p>
 * 网站统计日数据 前端控制器
 * </p>
 *
 * @author atguigu
 * @since 2022-07-12
 */
@RestController
@RequestMapping("/statistics/daily")
//@CrossOrigin
public class StatisticsDailyController {

    @Autowired
    private StatisticsDailyService statisticsDailyService;

    @PostMapping("/{date}")
    public R saveDailyRecord(@PathVariable String date) {
        statisticsDailyService.saveOrUpdateDailyRecord(date);
        return R.ok();
    }

    @GetMapping("/{type}/{begin}/{end}")
    public R getStatistic(@PathVariable String type, @PathVariable String begin, @PathVariable String end) {
        Map<String, Object> map = statisticsDailyService.getStatistic(type, begin, end);
        return R.ok().data(map);
    }

}

