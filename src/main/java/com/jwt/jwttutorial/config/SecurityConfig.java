package com.jwt.jwttutorial.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity //웹 보안을 활성화 하겠다
/*
추가적인 설정으로
1. WebSecurityConfigurer를 implements
2. WebSecurityConfigurerAdapter를 extends
 */
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                .antMatchers("/h2-console/**"
                        ,"/favicon.ico");

    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests() //httpServletRequest를 사용하는 요청들에 접근제한을 설정하겠다
                .antMatchers("/api/hello").permitAll() //api/hello에 대한 접근은 인증없이 허용하겠다.
                .anyRequest().authenticated();//나머지 요청들은 모두 인증을 받아야한다.
    }

}
