package com.atguigu.order.controller;


import com.atguigu.commonutils.R;
import com.atguigu.order.service.PayLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * <p>
 * 支付日志表 前端控制器
 * </p>
 *
 * @author atguigu
 * @since 2022-07-11
 */
@RestController
@RequestMapping("/orderservice/pay-log")
//@CrossOrigin
public class PayLogController {

    @Autowired
    private PayLogService payLogService;

    @PostMapping("/{orderId}")
    private R generateWxQRcode(@PathVariable String orderId) {
        Map<String, String> map = payLogService.generateWxQRcode(orderId);
        System.out.println("****** generate QR code => " + map);
        return R.ok().data(map);
    }

    @GetMapping("/{orderId}")
    private R checkPaymentStatus(@PathVariable String orderId) {
        Map<String, String> map = payLogService.checkPaymentStatus(orderId);
        System.out.println("****** checkStatus => " + map);

        if (map == null) {
            return R.error().message("Something wrong");
        }

        if ("SUCCESS".equals(map.get("trade_state"))) {
            payLogService.updateOrderStatus(map);
            return R.ok().message("Payment succeed");
        }
        return R.error().code(25000).message("Payment in progress");
    }

}

