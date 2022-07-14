package com.atguigu.edu_service.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Component
@FeignClient("service-order")
public interface OrderClient {

    @GetMapping("/orderservice/order/{courseId}/{memberId}")
    public boolean isBuy(@PathVariable("courseId") String courseId, @PathVariable("memberId") String memberId);
}
