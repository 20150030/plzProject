package com.lyj.securitydomo.config;

import jakarta.servlet.DispatcherType;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class CustomSecurityConfig {

    // UserDetailsService는 사용자 인증 정보를 가져오는 서비스로, Spring Security와 통합
    private final UserDetailsService userDetailsService;

    // SecurityFilterChain을 설정하여 각 요청의 보안 규칙을 정의
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // CSRF 설정
                .csrf(csrf -> csrf
                        // 특정 요청 경로에 대해 CSRF 보호를 비활성화
                        .ignoringRequestMatchers("/report/create", "/user/delete", "/user/logout")
                        // CSRF 토큰을 쿠키로 저장 (JavaScript에서도 사용 가능하도록 설정)
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                // 각 요청에 대한 권한 설정
                .authorizeHttpRequests(auth -> auth
                        // FORWARD 요청 허용
                        .dispatcherTypeMatchers(DispatcherType.FORWARD).permitAll()
                        // 로그인, 회원가입, 특정 경로는 인증 없이 접근 가능
                        .requestMatchers("/login", "/signup", "/replies/**", "/user/**", "/", "/all", "/posting/**", "/view/**").permitAll()
                        // POST 요청의 특정 경로에 대해 접근 허용
                        .requestMatchers(HttpMethod.POST, "/report/create").permitAll()
                        // 관리자 경로는 ADMIN 권한 필요
                        .requestMatchers("/admin/**").hasAuthority("ADMIN")
                        // 정적 리소스 (이미지, CSS, JS 등)는 인증 없이 접근 허용
                        .requestMatchers("/images/**", "/css/**", "/js/**", "/webjars/**").permitAll()
                        // 그 외 모든 요청은 인증 필요
                        .anyRequest().authenticated())
                // 로그인 설정
                .formLogin(form -> form
                        // 사용자 정의 로그인 페이지 경로
                        .loginPage("/user/login")
                        // 로그인 처리를 위한 URL
                        .loginProcessingUrl("/loginProcess")
                        // 로그인 성공 시 이동할 페이지
                        .defaultSuccessUrl("/posting/list")
                        // 로그인 실패 시 이동할 페이지
                        .failureUrl("/user/login?error=true"))
                // 로그아웃 설정
                .logout(logout -> logout
                        // 로그아웃 요청 URL
                        .logoutUrl("/user/logout")
                        // 로그아웃 성공 후 리디렉션 경로
                        .logoutSuccessUrl("/")
                        // 세션 무효화
                        .invalidateHttpSession(true)
                        // 인증 정보 제거
                        .clearAuthentication(true)
                        // 로그아웃 URL은 인증 없이 접근 가능
                        .permitAll());

        // 사용자 인증 및 비밀번호 암호화를 설정
        AuthenticationManagerBuilder auth = http.getSharedObject(AuthenticationManagerBuilder.class);
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());

        // 최종 SecurityFilterChain 반환
        return http.build();
    }

    // 비밀번호 암호화를 위한 BCryptPasswordEncoder Bean 등록
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}