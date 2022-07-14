package com.atguigu.cms.service;

import com.atguigu.cms.entity.Banner;
import com.baomidou.mybatisplus.extension.service.IService;

import java.util.List;

/**
 * <p>
 * 首页banner表 服务类
 * </p>
 *
 * @author atguigu
 * @since 2022-07-05
 */
public interface BannerService extends IService<Banner> {

    List<Banner> selectAll();
}
