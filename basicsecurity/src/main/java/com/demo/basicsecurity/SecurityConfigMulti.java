package com.demo.basicsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class RestSecurityConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain restSecurityFilterChain(HttpSecurity http) throws Exception {

        http
                .antMatcher("/api/**")
                .authorizeRequests()
                .antMatchers("/api/**").permitAll()
                .anyRequest().authenticated();

        // 인증 필터 별도 구현
        http.addFilter(restAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();

    }
}

@Configuration
@EnableWebSecurity
class FormSecurityConfig {

    @Bean
    public SecurityFilterChain formSecurityFilterChain(HttpSecurity http) throws Exception {

        http
                .antMatcher("/web/**")
                .authorizeRequests()
                .antMatchers("/index","/").permitAll()
                .anyRequest().authenticated();

        http.formLogin()
                .loginPage("/login")
                .defaultSuccessUrl("/")
                .permitAll();

        return http.build();

    }
}