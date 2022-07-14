package com.atguigu.ucenter.mapper;

import com.atguigu.ucenter.entity.Member;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;

import java.util.Map;

/**
 * <p>
 * 会员表 Mapper 接口
 * </p>
 *
 * @author atguigu
 * @since 2022-07-05
 */

@Mapper
public interface MemberMapper extends BaseMapper<Member> {

    Integer getDailyRegisterRecord(String date);
    Integer getDailyLoginRecord(String date);
}
