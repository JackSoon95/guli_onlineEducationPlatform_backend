package com.atguigu.cms.service.impl;

import com.atguigu.cms.entity.Banner;
import com.atguigu.cms.mapper.BannerMapper;
import com.atguigu.cms.service.BannerService;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * <p>
 * 首页banner表 服务实现类
 * </p>
 *
 * @author atguigu
 * @since 2022-07-05
 */
@Service
public class BannerServiceImpl extends ServiceImpl<BannerMapper, Banner> implements BannerService {

    @Override
    @Cacheable(value = "banner", key = "'selectIndexList'")
    public List<Banner> selectAll() {
        QueryWrapper<Banner> wrapper = new QueryWrapper<>();
        wrapper.orderByDesc("id");
        wrapper.last("limit 2");

        List<Banner> list = baseMapper.selectList(wrapper);
        return list;
    }
}
