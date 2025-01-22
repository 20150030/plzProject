package com.lyj.securitydomo.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.time.LocalDate;

@NoArgsConstructor
@AllArgsConstructor
@Data
@Entity


public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id", nullable = false) // 기존 id 필드를 user_id로 변경
    private Long userId;

    @Column(nullable = false, length = 50)
    private String name; // 일반 이름 필드

    @Column(nullable = false, unique = true, length = 50)
    private String username; //로그인아이디

    @Column(nullable = false, length = 255)
    private String password; // 비밀번호

    @Column(nullable = false, length = 255)
    private String email; // 이메일

    @Column(nullable = false)
    private String role; // 권한 정보

    // 추가 필드들
    @Column(nullable = false)
    private LocalDate birthDate = LocalDate.of(2000, 11, 12); //생년월일

    @Column(nullable = false)
    private String gender; //성별

    @Column(nullable = false, length = 50)
    private String city; //시

    @Column(nullable = false, length = 50)
    private String state; //구

    private LocalDate signupDate;//가입날짜

    @PrePersist
    protected void onCreate() {
        this.signupDate = LocalDate.now();
    }
    public Long getUserId() {
        return this.userId;
    }
}