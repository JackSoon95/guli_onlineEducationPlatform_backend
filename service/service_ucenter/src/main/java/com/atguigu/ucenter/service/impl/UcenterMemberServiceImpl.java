package com.atguigu.ucenter.service.impl;

import com.atguigu.commonutils.JwtUtils;
import com.atguigu.commonutils.MD5;
import com.atguigu.servicebase.exceptionHandler.GuliException;
import com.atguigu.ucenter.entity.Member;
import com.atguigu.ucenter.entity.vo.RegisterVo;
import com.atguigu.ucenter.mapper.MemberMapper;
import com.atguigu.ucenter.service.UcenterMemberService;
import org.springframework.util.StringUtils;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>
 * 会员表 服务实现类
 * </p>
 *
 * @author atguigu
 * @since 2022-07-05
 */
@Service
public class UcenterMemberServiceImpl extends ServiceImpl<MemberMapper, Member> implements UcenterMemberService {

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    @Override
    public String login(Member member) {
        String mobile = member.getMobile();
        String password = member.getPassword();

        if (StringUtils.isEmpty(mobile) || StringUtils.isEmpty(password)) {
            throw new GuliException(20001, "Please enter your phone no and password");
        }

        QueryWrapper<Member> wrapper = new QueryWrapper<>();
        wrapper.eq("mobile", mobile);
        Member result = baseMapper.selectOne(wrapper);

        if (result == null) {
            throw new GuliException(20001, "User not found, please check your phone no");
        }

        if(!MD5.encrypt(password).equals(result.getPassword())) {
            throw new GuliException(20001, "Wrong password");
        }

        if(result.getIsDisabled()) {
            throw new GuliException(20001, "Invalid user");
        }

        result.setGmtModified(new Date());
        baseMapper.updateById(member);

        String jwtToken = JwtUtils.getJwtToken(result.getId(), result.getNickname());

        return jwtToken;
    }

    @Override
    public void register(RegisterVo registerVo) {
        String mobile = registerVo.getMobile();
        String password = registerVo.getPassword();
        String nickname = registerVo.getNickname();
        String code = registerVo.getCode();

        if (StringUtils.isEmpty(mobile) || StringUtils.isEmpty(password) || StringUtils.isEmpty(nickname)
                || StringUtils.isEmpty(code)) {
            throw new GuliException(20001, "Please complete the info.");
        }

        //String redisCode = redisTemplate.opsForValue().get(mobile);
        //if(redisCode.equals(code)) {
        //    throw new GuliException(20001, "wrong code");
        //}

        QueryWrapper<Member> wrapper = new QueryWrapper<>();
        wrapper.eq("mobile", mobile);
        int count = baseMapper.selectCount(wrapper);

        if (count > 0) {
            throw new GuliException(20001, "Mobile no was registered");
        }

        password = MD5.encrypt(password);
        Member member = new Member();
        member.setAvatar("http://thirdwx.qlogo.cn/mmopen/vi_32/UEVqZKDCKVXJiazYbOM1A8WX4STK0UtqCygsAicEMQvCeyb7rKwUgLdo4efTVcERe21w2fOWw3KFbxXmMqfM4FOQ/132");
        member.setIsDisabled(false);
        member.setNickname(nickname);
        member.setMobile(mobile);
        member.setPassword(password);

        baseMapper.insert(member);
    }

    @Override
    public Member getOpenIdMember(String openId) {
        QueryWrapper<Member> wrapper = new QueryWrapper<>();
        wrapper.eq("openid",openId);

        return baseMapper.selectOne(wrapper);
    }

    @Override
    public Map<String, Object> getDailyRecord(String date) {
        Integer registerCount = baseMapper.getDailyRegisterRecord(date);
        Integer loginCount = baseMapper.getDailyLoginRecord(date);
        Map<String, Object> map = new HashMap<>();
        map.put("registerCount", registerCount);
        map.put("loginCount", loginCount);
        return map;
    }

}
