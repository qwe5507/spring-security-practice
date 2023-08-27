package com.demo.basicsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

//@Configuration
//@EnableWebSecurity
public class SecurityConfigMulti {

//    @Bean
//    @Order(Ordered.HIGHEST_PRECEDENCE)
//    @Order(0)
    public SecurityFilterChain securityFilterChain1(HttpSecurity http) throws Exception {

        http
            .antMatcher("/admin/**")
            .authorizeRequests()
            .anyRequest().authenticated();

        http.httpBasic();

        return http.build();

    }
}

//@Configuration
//@EnableWebSecurity
class SecurityConfig2 {

//    @Bean
//    @Order(1)
    public SecurityFilterChain securityFilterChain2(HttpSecurity http) throws Exception {

        http
            .authorizeRequests()
            .anyRequest().permitAll();

        http.formLogin();

        return http.build();

    }
}