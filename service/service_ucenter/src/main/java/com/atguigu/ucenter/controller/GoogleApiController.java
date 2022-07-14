package com.atguigu.ucenter.controller;

import com.atguigu.commonutils.JwtUtils;
import com.atguigu.servicebase.exceptionHandler.GuliException;
import com.atguigu.ucenter.entity.Member;
import com.atguigu.ucenter.service.UcenterMemberService;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;


import java.util.Collections;
import java.util.Date;

@Controller
@CrossOrigin
@RequestMapping("/google")
public class GoogleApiController {
    @Autowired
    private UcenterMemberService ucenterMemberService;

    @PostMapping("/login")
    public String loginGoogle(@RequestBody String credential) throws Exception{
        GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), new GsonFactory())
                // Specify the CLIENT_ID of the app that accesses the backend:
                .setAudience(Collections.singletonList("474248532752-jpt3koueghpvb4bs64ivrfgsf74pf8gl.apps.googleusercontent.com"))
                // Or, if multiple clients access the backend:
                //.setAudience(Arrays.asList(CLIENT_ID_1, CLIENT_ID_2, CLIENT_ID_3))
                .build();

        String idTokenString = credential.substring(credential.indexOf('=') + 1, credential.lastIndexOf('&'));
        String csrfToken = credential.substring(credential.lastIndexOf('=') + 1);

        GoogleIdToken idToken = verifier.verify(idTokenString);

        if (idToken != null) {
            Payload payload = idToken.getPayload();

            // Print user identifier
            String openId = payload.getSubject();
            //System.out.println("User ID: " + userId);

            // Get profile information from payload
            //System.out.println(payload);
            //String email = payload.getEmail();
            //boolean emailVerified = Boolean.valueOf(payload.getEmailVerified());
            //String name = (String) payload.get("name");
            //String pictureUrl = (String) payload.get("picture");
            //String locale = (String) payload.get("locale");
            //String familyName = (String) payload.get("family_name");
            //String givenName = (String) payload.get("given_name");
            //...
            Member member = ucenterMemberService.getOpenIdMember(openId);
            if (member == null) {
                member = new Member();
                member.setOpenid(openId);
                member.setNickname((String) payload.get("name"));
                member.setAvatar((String) payload.get("picture"));

                ucenterMemberService.save(member);
            }
            member.setGmtModified(new Date());
            ucenterMemberService.updateById(member);

            String jwtToken = JwtUtils.getJwtToken(member.getId(), member.getNickname());
            return "redirect:http://localhost:3000?tracingId=" + jwtToken + "&csrfToken=" + csrfToken;
        } else {
            throw new GuliException(20001,"Invalid ID token");
        }
    }
}
