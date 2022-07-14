package com.atguigu.aclservice.helper;

import com.atguigu.aclservice.entity.Permission;
import com.atguigu.aclservice.service.PermissionService;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class PermissionHelper {
    public static List<Permission> build(List<Permission> permissions) {
        List<Permission> result = new ArrayList<>();
        for (Permission permission : permissions) {
            if ("0".equals(permission.getPid())) {
                permission.setLevel(1);
                result.add(buildChildren(permission, permissions));
            }
        }

        return result;
    }

    public static Permission buildChildren(Permission permission, List<Permission> permissions) {
        List<Permission> children = new ArrayList<>();
        for (Permission it : permissions) {
            if (it.getPid().equals(permission.getId())) {
                it.setLevel(permission.getLevel() + 1);
                children.add(buildChildren(it, permissions));
            }
        }
        permission.setChildren(children);

        return permission;
    }

}
