package com.atguigu.order.client;

import com.atguigu.commonutils.user.CourseWebVoOrder;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Component
@FeignClient("service-edu")
public interface EduServiceClient {
    @GetMapping("/eduservice/courseFront/object/{id}")
    public CourseWebVoOrder getCourseObjectsById(@PathVariable("id") String id);
}
