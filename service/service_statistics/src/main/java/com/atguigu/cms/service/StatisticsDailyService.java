package com.atguigu.cms.service;

import com.atguigu.cms.entity.StatisticsDaily;
import com.baomidou.mybatisplus.extension.service.IService;

import java.util.Map;

/**
 * <p>
 * 网站统计日数据 服务类
 * </p>
 *
 * @author atguigu
 * @since 2022-07-12
 */
public interface StatisticsDailyService extends IService<StatisticsDaily> {

    void saveOrUpdateDailyRecord(String date);

    Map<String, Object> getStatistic(String type, String begin, String end);
}
