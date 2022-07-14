package com.atguigu.order.service;

import com.atguigu.order.entity.PayLog;
import com.baomidou.mybatisplus.extension.service.IService;

import java.util.Map;

/**
 * <p>
 * 支付日志表 服务类
 * </p>
 *
 * @author atguigu
 * @since 2022-07-11
 */
public interface PayLogService extends IService<PayLog> {

    Map generateWxQRcode(String orderId);

    Map<String, String> checkPaymentStatus(String orderId);

    void updateOrderStatus(Map<String, String> map);
}
