package com.atguigu.ucenter.controller;


import com.atguigu.commonutils.JwtUtils;
import com.atguigu.commonutils.MD5;
import com.atguigu.commonutils.R;
import com.atguigu.commonutils.user.UcenterMemberOrder;
import com.atguigu.servicebase.exceptionHandler.GuliException;
import com.atguigu.ucenter.entity.Member;
import com.atguigu.ucenter.entity.vo.RegisterVo;
import com.atguigu.ucenter.service.UcenterMemberService;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * <p>
 * 会员表 前端控制器
 * </p>
 *
 * @author atguigu
 * @since 2022-07-05
 */
@RestController
@RequestMapping("/ucenter/member")
//@CrossOrigin
public class UcenterMemberController {

    @Autowired
    private UcenterMemberService ucenterMemberService;

    @PostMapping("/login")
    public R login(@RequestBody Member member) {
        String token = ucenterMemberService.login(member);
        return R.ok().data("token", token);
    }

    @PostMapping("/register")
    public R register(@RequestBody RegisterVo registerVo) {
        ucenterMemberService.register(registerVo);
        return R.ok();
    }

    @GetMapping("")
    public R getMemberByToken(HttpServletRequest request) {
        String memberId = JwtUtils.getMemberIdByJwtToken(request);
        Member member = null;
        try {
            member = ucenterMemberService.getById(memberId);
        } catch (GuliException e) {
            return R.error().code(e.getCode()).message(e.getMsg());
        }
        return R.ok().data("member", member);
    }

    @GetMapping("/{id}")
    public UcenterMemberOrder getMemberById(@PathVariable String id) {
        Member member = ucenterMemberService.getById(id);
        UcenterMemberOrder result = new UcenterMemberOrder();
        BeanUtils.copyProperties(member, result);

        return result;
    }

    @GetMapping("/count/{date}")
    public R getDailyRecord(@PathVariable String date) {
        Map<String, Object> map = ucenterMemberService.getDailyRecord(date);
        return R.ok().data(map);
    }
}

