package com.atguigu.order.controller;


import com.atguigu.commonutils.JwtUtils;
import com.atguigu.commonutils.R;
import com.atguigu.order.entity.Order;
import com.atguigu.order.service.OrderService;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

/**
 * <p>
 * 订单 前端控制器
 * </p>
 *
 * @author atguigu
 * @since 2022-07-11
 */
@RestController
@RequestMapping("/orderservice/order")
//@CrossOrigin
public class OrderController {
    @Autowired
    private OrderService orderService;

    @PostMapping("/{courseId}")
    public R newOrder(@PathVariable String courseId, HttpServletRequest request) {
        String memberId = JwtUtils.getMemberIdByJwtToken(request);
        if (memberId.equals("")) {
            return R.error().code(20001).message("Please Login");
        }

        String orderNo = orderService.createNewOrder(courseId, memberId);
        return R.ok().data("orderId", orderNo);
    }

    @GetMapping("/{orderId}")
    public R getOrderById(@PathVariable String orderId) {
        QueryWrapper<Order> wrapper = new QueryWrapper<>();
        wrapper.eq("order_no", orderId);
        Order order = orderService.getOne(wrapper);
        return R.ok().data("item", order);
    }

    @GetMapping("/{courseId}/{memberId}")
    public boolean isBuy(@PathVariable String courseId, @PathVariable String memberId){
        QueryWrapper<Order> wrapper = new QueryWrapper<>();
        wrapper.eq("course_id", courseId);
        wrapper.eq("member_id", memberId);
        wrapper.eq("status", true);
        int count = orderService.count(wrapper);
        return count > 0;
    }

}

