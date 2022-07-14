package com.atguigu.order.service.impl;

import com.atguigu.commonutils.user.CourseWebVoOrder;
import com.atguigu.commonutils.user.UcenterMemberOrder;
import com.atguigu.order.client.EduServiceClient;
import com.atguigu.order.client.UcenterClient;
import com.atguigu.order.entity.Order;
import com.atguigu.order.mapper.OrderMapper;
import com.atguigu.order.service.OrderService;
import com.atguigu.order.utils.OrderNoUtil;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * <p>
 * 订单 服务实现类
 * </p>
 *
 * @author atguigu
 * @since 2022-07-11
 */
@Service
public class OrderServiceImpl extends ServiceImpl<OrderMapper, Order> implements OrderService {

    @Autowired
    private EduServiceClient eduServiceClient;

    @Autowired
    private UcenterClient ucenterClient;

    @Override
    public String createNewOrder(String courseId, String memberId) {
        CourseWebVoOrder courseInfoOrder = eduServiceClient.getCourseObjectsById(courseId);
        UcenterMemberOrder userInfoOrder = ucenterClient.getMemberById(memberId);

        Order order = new Order();
        order.setOrderNo(OrderNoUtil.getOrderNo());
        order.setCourseId(courseId);
        order.setCourseTitle(courseInfoOrder.getTitle());
        order.setCourseCover(courseInfoOrder.getCover());
        order.setTeacherName(courseInfoOrder.getTeacherName());
        order.setTotalFee(courseInfoOrder.getPrice());
        order.setMemberId(memberId);
        order.setMobile(userInfoOrder.getMobile());
        order.setNickname(userInfoOrder.getNickname());
        order.setStatus(0);
        order.setPayType(1);
        baseMapper.insert(order);

        return order.getOrderNo();
    }
}
