package com.shop.config;

import com.shop.service.MemberService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import org.springframework.security.config.annotation.web.builders.WebSecurity;


@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig {

    MemberService memberService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .formLogin(formLogin -> formLogin
                        .loginPage("/members/login")    //로그인 페이지 설정
                        .defaultSuccessUrl("/")            //로그인 성공 시 이동할 URL 설정
                        .usernameParameter("email")        //로그인 시 사용할 파라미터
                        .failureUrl("/members/login/error"))    //로그인 실패 시 이동할 URL 설정
                .logout(logout -> logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/members/logout"))    //로그아웃 URL 설정
                        .logoutSuccessUrl("/members/"));    //로그아웃 성공 시 이동할 URL 설정

        //시큐리티 처리에 HTTPServletRequest 이용
        http.authorizeHttpRequests(authorizeRequests ->
                authorizeRequests
                        .requestMatchers("/css/**", "/js/**", "/img/**").permitAll()    //static 디렉터리의 하위 파일은 인증을 무시하도록 설정
                        .requestMatchers("/", "/members/**", "/item/**", "/images/**").permitAll()  //모든 사용자가 인증(로그인)없이 해당 경로에 접근할 수 있도록 설정
                        .requestMatchers("/admin/**").hasRole("ADMIN")  //admin으로 시작하는 경로는 관리자 권한일 경우 접근 가능하도록 설정
                        .anyRequest().authenticated());     /*나머지 경로들은 모두 인증을 요구하도록 설정

        //인증되지 않은 사용자가 리소스에 접근하였을 때 수행되는 핸들러를 등록*/
        http.exceptionHandling(exceptionHandling ->
                exceptionHandling.authenticationEntryPoint(new CustomAuthenticationEntryPoint()));


        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
