package com.atguigu.cms.schedule;

import com.atguigu.cms.service.StatisticsDailyService;
import com.atguigu.commonutils.DateUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class ScheduledTask {

    @Autowired
    private StatisticsDailyService statisticsService;

    @Scheduled(cron = "0 0 1 * * ?")
    public void task2() {
        statisticsService.saveOrUpdateDailyRecord(DateUtil.formatDate(DateUtil.addDays(new Date(), -1)));
    }
}
