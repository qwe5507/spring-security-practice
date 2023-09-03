package com.demo.coresecurity.security.configs;

import com.demo.coresecurity.security.handler.FormAccessDeniedHandler;
import com.demo.coresecurity.security.provider.FormAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
@RequiredArgsConstructor
@Order(1)
public class SecurityConfig {

    //    @Bean
//    public UserDetailsManager users() {
//
//        String password = passwordEncoder().encode("1111");
//
//        UserDetails user = User.builder()
//                .username("user")
//                .password(password)
//                .roles("USER")
//                .build();
//
//        UserDetails manager = User.builder()
//                .username("manager")
//                .password(password)
//                .roles("MANAGER")
//                .build();
//
//        UserDetails admin = User.builder()
//                .username("admin")
//                .password(password)
//                .roles("ADMIN", "USER", "MANAGER")
//                .build();
//
//        return new InMemoryUserDetailsManager(user, manager, admin);
//    }

    @Autowired
    private AuthenticationDetailsSource formAuthenticationDetailsSource;

    @Autowired
    private AuthenticationFailureHandler formAuthenticationFailureHandler;

    @Autowired
    private AuthenticationSuccessHandler formAuthenticationSuccessHandler;

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        // 보안필터를 거치지 않는다.
        return (web) -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider(){
        return new FormAuthenticationProvider(passwordEncoder());
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(authenticationProvider());
        authenticationManagerBuilder.parentAuthenticationManager(null);

        http
                .authorizeRequests()
                .antMatchers("/", "/users", "/user/login/**", "/error", "/login**").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .defaultSuccessUrl("/")
                .authenticationDetailsSource(formAuthenticationDetailsSource)
                .successHandler(formAuthenticationSuccessHandler)
                .failureHandler(formAuthenticationFailureHandler)
                .permitAll();
        http
                .exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                .accessDeniedPage("/denied")
                .accessDeniedHandler(accessDeniedHandler());

        http.csrf().disable();

        return http.build();
    }
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers("/mypage").hasRole("USER")
//                .antMatchers("/messages").hasRole("MANAGER")
//                .antMatchers("/config").hasRole("ADMIN")
////                .antMatchers("/", "user/login/**", "/users", "/login*").permitAll()
//                .antMatchers("/**").permitAll()
//                .anyRequest().authenticated();
//
//        http.formLogin()
//                .loginPage("/login")
//                .loginProcessingUrl("/login_proc")
//                .defaultSuccessUrl("/")
//                .successHandler(formAuthenticationSuccessHandler)
//                .failureHandler(formAuthenticationFailureHandler)
//                .authenticationDetailsSource(formAuthenticationDetailsSource)
//                .permitAll();
//
//        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
//        authenticationManagerBuilder.authenticationProvider(authenticationProvider());
//        authenticationManagerBuilder.parentAuthenticationManager(null);
////        http.authenticationProvider(authenticationProvider());
//
//        http.exceptionHandling()
//                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
//                .accessDeniedPage("/denied")
//                .accessDeniedHandler(accessDeniedHandler());
//
//        http.csrf().disable();
//
//        return http.build();
//    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        FormAccessDeniedHandler accessDeniedHandler = new FormAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");

        return accessDeniedHandler;
    }
}
