package com.demo.basicsecurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index(HttpSession session) {

        Authentication authentication1 = SecurityContextHolder.getContext().getAuthentication();
        SecurityContext context = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);//SPRING_SECURITY_CONTEXT
        Authentication authentication2 = context.getAuthentication();
        // authentication1 == authentication2

        return "home";
    }

    @GetMapping("/thread")
    public String thread() {
        Authentication authentication1 = SecurityContextHolder.getContext().getAuthentication();
        System.out.println(authentication1);
        new Thread(
                new Runnable() {
                    @Override
                    public void run() {
                        Authentication authentication2 = SecurityContextHolder.getContext().getAuthentication();
                        System.out.println(authentication2);
                        //SecurityContextHolder.MODE_INHERITABLETHREADLOCAL 옵션이 아니라면 NULL
                    }
                }
        ).start();
        return "thread";
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @GetMapping("/admin/pay")
    public String adminPay() {
        return "adminPay";
    }

    @GetMapping("/admin/**")
    public String admin() {
        return "admin";
    }

    @GetMapping("/denied")
    public String denied() {
        return "Access is denied";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
