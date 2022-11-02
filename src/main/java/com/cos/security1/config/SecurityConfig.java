package com.cos.security1.config;

import com.cos.security1.config.auth.oauth.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity //스프링 시큐리티 필터(여기서는 SecurityConfig)가 스프링 필터체인에 등록됨.
@EnableGlobalMethodSecurity(securedEnabled = true , prePostEnabled = true) //securedEnabled = true :secure 어노테이션 활성화, prePostEnabled = true : preAuthorize 어노테이션 활성화
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final PrincipalOauth2UserService principalOauth2UserService;

    //해당 메서드의 리턴되는 오브젝트를 ioc로 등록
    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated() //인증만 되면 들어갈수있는 주소
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') OR hasRole('ROLE_MANAGER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login") //login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인 진행해줌. => controller /login 안만들어도됨
                .defaultSuccessUrl("/") // 로그인하기전에 요청한 그 페이지로 보내줌
                .and()
                .oauth2Login()
                .loginPage("/loginForm") //구글 로그인이 완료된 후의 처리가 필요함 Tip.코드x (엑세스 토큰 + 사용자 프로필정보 O)
                .userInfoEndpoint()// 1. 인가 코드 받기(인증) 2. 인가코드로 엑세스 토큰 받기(권한) 3.엑세스 토큰으로 사용자 프로필정보를 가져오고  4. 그 정보를 토대로 회원가입을 자동으로 진행시키기도 함
                .userService(principalOauth2UserService);// 4-2 구글 로그인에서 (이메일, 전화번호, 이름, 아이디) 제공해줌 but 집주소가 필요하다면? -> 추가적인 회원가입 창이 나와서 회원가입을 진행하기도 함
    }
}
