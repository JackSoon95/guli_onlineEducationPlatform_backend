package com.atguigu.cms.service.impl;

import com.atguigu.cms.client.EduClient;
import com.atguigu.cms.client.UcenterClient;
import com.atguigu.cms.entity.StatisticsDaily;
import com.atguigu.cms.mapper.StatisticsDailyMapper;
import com.atguigu.cms.service.StatisticsDailyService;
import com.atguigu.commonutils.R;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * <p>
 * 网站统计日数据 服务实现类
 * </p>
 *
 * @author atguigu
 * @since 2022-07-12
 */
@Service
public class StatisticsDailyServiceImpl extends ServiceImpl<StatisticsDailyMapper, StatisticsDaily> implements StatisticsDailyService {

    @Autowired
    private UcenterClient ucenterClient;

    @Autowired
    private EduClient eduClient;

    @Override
    public void saveOrUpdateDailyRecord(String date) {
        QueryWrapper<StatisticsDaily> exist = new QueryWrapper<>();
        exist.eq("date_calculated", date);
        baseMapper.delete(exist);

        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        LocalDate dateDtf = LocalDate.parse(date, dtf);
        dateDtf = dateDtf.minusDays(1);


        R memberR = ucenterClient.getDailyRecord(date);
        Integer registerCount = (Integer) memberR.getData().get("registerCount");
        Integer loginCount = (Integer) memberR.getData().get("loginCount");

        R courseR = eduClient.getCount();
        QueryWrapper<StatisticsDaily> wrapper = new QueryWrapper<>();
        wrapper.eq("date_calculated", dateDtf);
        StatisticsDaily yesterday = baseMapper.selectOne(wrapper);
        if (yesterday == null) {
            yesterday = new StatisticsDaily();
            yesterday.setCourseNum(0);
            yesterday.setVideoViewNum(0);
        }
        Integer viewCount = (Integer) courseR.getData().get("courseView");
        Integer courseCreated = (Integer) courseR.getData().get("courseCreated");
        viewCount = viewCount - yesterday.getVideoViewNum();
        courseCreated = courseCreated - yesterday.getCourseNum();

        StatisticsDaily record = new StatisticsDaily();
        record.setRegisterNum(registerCount);
        record.setLoginNum(loginCount);
        record.setVideoViewNum(viewCount);
        record.setCourseNum(courseCreated);
        record.setDateCalculated(date);

        baseMapper.insert(record);
    }

    @Override
    public Map<String, Object> getStatistic(String type, String begin, String end) {
        QueryWrapper<StatisticsDaily> wrapper = new QueryWrapper<>();
        wrapper.between("date_calculated" ,begin, end);
        wrapper.select("date_calculated", type);
        List<StatisticsDaily> statisticsDailies = baseMapper.selectList(wrapper);

        List<Integer> typeList = new ArrayList<>();
        List<String> dateList = new ArrayList<>();

        for (int i = 0; i < statisticsDailies.size(); i++) {
            StatisticsDaily record = statisticsDailies.get(i);

            dateList.add(record.getDateCalculated());

            switch(type) {
                case "login_num":
                    typeList.add(record.getLoginNum());
                    break;
                case "register_num":
                    typeList.add(record.getRegisterNum());
                    break;
                case "video_view_num":
                    typeList.add(record.getVideoViewNum());
                    break;
                case "course_num":
                    typeList.add(record.getCourseNum());
                    break;
                default:
                    break;
            }
        }

        Map<String, Object> map = new HashMap<>();
        map.put("typeList", typeList);
        map.put("dateList", dateList);
        return map;
    }
}
