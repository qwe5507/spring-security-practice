package com.demo.basicsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

//@Configuration
public class SecurityConfigCsrf {

//    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 스프링 시큐리티 5.4에 맞춘 강의 예제
        http.authorizeHttpRequests(authorizeHttpRequests ->
                authorizeHttpRequests
                        .anyRequest().authenticated());

        http.formLogin();

        http.csrf();
//        http.csrf()
//                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());

        return http.build();
    }

}
