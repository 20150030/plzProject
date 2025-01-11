package com.lyj.securitydomo.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "report")
public class Report {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long reportId;  // 신고 ID 자동 생성

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "postId", nullable = false) // 신고 대상 게시글 외래 키
    private Post post;  // 신고 대상 게시글

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false) // 신고자 외래 키 (필수)
    private User user;

    @Enumerated(EnumType.STRING) // 문자열로 저장
    @Column(nullable = false)
    private ReportCategory category;  // 신고 분류 열거형 (SPAM, ABUSE 등)

    @Column(nullable = false, length = 255)
    private String reason;  // 신고 사유

    @Enumerated(EnumType.STRING) // 문자열로 저장
    @Column(nullable = false)
    private ReportStatus status;  // 신고 진행 상태 (PENDING, VISIBLE, HIDDEN)

    @Temporal(TemporalType.TIMESTAMP)
    private Date createdAt;  // 생성 날짜

    private boolean isVisible;  // 게시글의 비공개/공개 상태 공개(0) 비공개(1)

    public enum ReportCategory {
        SPAM,
        ABUSE,
        ADVERTISING,
        PROMOTION,
    }

    public enum ReportStatus {
        PENDING,   // 신고 처리 대기
        VISIBLE,   // 공개 상태
        HIDDEN     // 비공개 상태
    }

    // ReportStatus에 따라 isVisible 값을 설정하는 메서드
    public void setStatus(ReportStatus status) {
        this.status = status;
        // status가 VISIBLE이면 isVisible을 true로 설정하고, HIDDEN이면 false로 설정
        this.isVisible = (status == ReportStatus.VISIBLE);
    }

    @Override
    public String toString() {
        return "Report{" +
                "reportId=" + reportId +
                ", category=" + category +
                ", reason='" + reason + '\'' +
                ", status=" + status +
                ", createdAt=" + createdAt +
                ", isVisible=" + isVisible +
                ", user=" + (user != null ? user.getUsername() : "null") + // 유저 정보 추가
                '}';
    }
}