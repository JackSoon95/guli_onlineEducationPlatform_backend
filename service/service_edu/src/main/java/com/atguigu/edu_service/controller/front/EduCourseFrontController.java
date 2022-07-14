package com.atguigu.edu_service.controller.front;


import com.atguigu.commonutils.JwtUtils;
import com.atguigu.commonutils.R;
import com.atguigu.commonutils.user.CourseWebVoOrder;
import com.atguigu.edu_service.client.OrderClient;
import com.atguigu.edu_service.entity.vo.chapter.ChapterVo;
import com.atguigu.edu_service.entity.vo.front.CourseFrontFilterVo;
import com.atguigu.edu_service.entity.vo.front.CourseFrontRelatedVo;
import com.atguigu.edu_service.service.EduChapterService;
import com.atguigu.edu_service.service.EduCourseService;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/eduservice/courseFront")
//@CrossOrigin
public class EduCourseFrontController {
    @Autowired
    private EduCourseService eduCourseService;

    @Autowired
    private EduChapterService eduChapterService;

    @Autowired
    private OrderClient orderClient;

    @PostMapping("/page/{current}/{limit}")
    public R getPage(@PathVariable Integer current, @PathVariable Integer limit,
                     @RequestBody(required = false) CourseFrontFilterVo vo) {
        Map<String, Object> map = eduCourseService.getPageForFront(current, limit, vo);
        return R.ok().data(map);
    }

    @GetMapping("/{id}")
    public R getCourseInfoById(@PathVariable String id, HttpServletRequest request) {
        CourseFrontRelatedVo courseWebVo = eduCourseService.getCourseFrontInfoById(id);
        List<ChapterVo> chapters = eduChapterService.getChapterVideoById(id);

        String memberId = JwtUtils.getMemberIdByJwtToken(request);
        boolean isBuy = false;
        if (memberId != null && !memberId.equals("")) {
            isBuy = orderClient.isBuy(id, JwtUtils.getMemberIdByJwtToken(request));
        }

        return R.ok().data("courseWebVo", courseWebVo).data("chapterVideoList",chapters).data("isBuy", isBuy);
    }

    @GetMapping("/object/{id}")
    public CourseWebVoOrder getCourseObjectsById(@PathVariable String id) {
        CourseFrontRelatedVo courseWebVo = eduCourseService.getCourseFrontInfoById(id);
        CourseWebVoOrder courseWebVoOrder = new CourseWebVoOrder();
        BeanUtils.copyProperties(courseWebVo, courseWebVoOrder);

        return courseWebVoOrder;
    }

}
