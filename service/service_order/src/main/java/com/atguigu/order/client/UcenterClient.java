package com.atguigu.order.client;


import com.atguigu.commonutils.R;
import com.atguigu.commonutils.user.UcenterMemberOrder;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import javax.servlet.http.HttpServletRequest;

@Component
@FeignClient("service-ucenter")
public interface UcenterClient {

    @GetMapping("/ucenter/member/{id}")
    public UcenterMemberOrder getMemberById(@PathVariable("id") String id);
}
