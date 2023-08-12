package com.demo.basicsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated();

        http.formLogin();

        http.sessionManagement()
                .sessionFixation().none()// 기본값
                                         // none, migrateSession, newSession
//                .invalidSessionUrl("/invalid")      // 세션이 유효하지 않을 때 이동 할 페이지
                .maximumSessions(1)                 // 최대 허용 가능 세션 수 , -1 : 무제한 로그인 세션 허용
                .maxSessionsPreventsLogin(false)    // 동시 로그인 차단함,  false : 기존 세션 만료(default)
                .expiredUrl("/expired");            // 세션이 만료된 경우 이동 할 페이지


        return http.build();
    }
}
