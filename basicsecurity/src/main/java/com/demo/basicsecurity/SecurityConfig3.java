package com.demo.basicsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig3 {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 스프링 시큐리티 5.4에 맞춘 강의 예제
        http.authorizeHttpRequests(authorizeHttpRequests ->
                authorizeHttpRequests
                        .antMatchers("/user").hasRole("USER")
                        .anyRequest().permitAll()
        );

        http.formLogin();

        // 상위스레드와 하위스레드간 시큐리티 컨텍스트 공유
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);

        return http.build();
    }
}