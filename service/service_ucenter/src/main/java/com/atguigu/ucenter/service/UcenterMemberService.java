package com.atguigu.ucenter.service;

import com.atguigu.ucenter.entity.Member;
import com.atguigu.ucenter.entity.vo.RegisterVo;
import com.baomidou.mybatisplus.extension.service.IService;

import java.util.Map;

/**
 * <p>
 * 会员表 服务类
 * </p>
 *
 * @author atguigu
 * @since 2022-07-05
 */
public interface UcenterMemberService extends IService<Member> {

    String login(Member member);

    void register(RegisterVo registerVo);

    Member getOpenIdMember(String openId);

    Map<String, Object> getDailyRecord(String date);
}
