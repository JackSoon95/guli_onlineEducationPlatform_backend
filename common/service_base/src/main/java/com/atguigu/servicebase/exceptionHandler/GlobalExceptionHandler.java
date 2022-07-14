package com.atguigu.servicebase.exceptionHandler;

import com.atguigu.commonutils.R;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;

@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {
    @ExceptionHandler(Exception.class)
    @ResponseBody
    public R error(Exception e) {
        System.out.println(e.getMessage());
        return R.error().message("执行了全局异常处理");
    }

    //specific exception
    @ExceptionHandler(ArithmeticException.class)
    @ResponseBody
    public R error(ArithmeticException e) {
        System.out.println(e.getMessage());
        return R.error().message("执行了特定异常处理");
    }

    //customized exception
    @ExceptionHandler(GuliException.class)
    @ResponseBody
    public R error(GuliException e) {
        log.error(e.getMessage());
        return R.error().code(e.getCode()).message(e.getMsg());
    }
}
