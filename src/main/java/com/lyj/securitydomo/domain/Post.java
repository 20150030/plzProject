package com.lyj.securitydomo.domain;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.BatchSize;

import java.util.*;
import java.util.stream.Collectors;

/**
 * 게시글(Post) 엔티티
 * - 게시글 데이터 및 관련 동작 정의
 */
@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@ToString(exclude = "imageSet")
public class Post extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long postId; // 게시글 ID 자동 생성

    private String title; // 제목

    private String contentText; // 게시글 본문 내용

    private Integer requiredParticipants; // 모집 인원

    @Enumerated(EnumType.STRING)
    private Status status; // 모집 상태 (모집중 또는 모집완료)

    public enum Status {
        모집중, 모집완료
    }

    private double lat; // 위도
    private double lng; // 경도

    @Builder.Default
    private boolean isVisible = true; // 기본값: 게시글이 공개 상태

    @ManyToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "user_id")
    private User user; // 작성자 정보

    // 신고 (Report)와 연관 관계 설정
    @OneToMany(mappedBy = "post", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<Report> reports = new ArrayList<>();

    // 신청 (Request)와 연관 관계 설정
    @OneToMany(mappedBy = "post", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<Request> requests = new ArrayList<>();

    // 댓글 (Reply)와 연관 관계 설정
    @OneToMany(mappedBy = "post", fetch = FetchType.LAZY, cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonManagedReference  // Post 객체에서 Reply 객체를 직렬화할 때 포함
    @Builder.Default
    private List<Reply> replies = new ArrayList<>();  // 댓글 리스트


    // 이미지와 연관 관계 설정
    @OneToMany(mappedBy = "post",
            fetch = FetchType.LAZY,
            cascade = CascadeType.ALL,
            orphanRemoval = true)
    @Builder.Default
    @BatchSize(size = 20)
    private Set<pPhoto> imageSet = Collections.synchronizedSet(new HashSet<>());

    @Temporal(TemporalType.DATE)
    private Date deadline; // 모집 마감일

    @Column(nullable = false)
    @Builder.Default
    private boolean firstComeFirstServe = false; // 선착순 모집 여부


    // ===== 메서드 =====

    /**
     * 썸네일 이미지 링크를 가져오는 메서드
     * 업로드된 이미지가 없으면 랜덤 이미지를 반환합니다.
     *
     * @return 이미지 링크
     */
    public String getThumbnail() {
        return (imageSet != null && !imageSet.isEmpty())
                ? imageSet.iterator().next().getThumbnailLink()
                : pPhoto.getRandomImage();
    }

    /**
     * 원본 이미지 링크 목록을 가져오는 메서드
     *
     * @return 원본 이미지 링크 목록
     */
    public List<String> getOriginalImageLinks() {
        return imageSet.stream()
                .sorted()
                .map(pPhoto::getOriginalLink)
                .collect(Collectors.toList());
    }

    /**
     * 이미지 추가 메서드
     *
     * @param uuid     고유 식별자
     * @param fileName 파일 이름
     */
    public void addImage(String uuid, String fileName) {
        pPhoto image = pPhoto.builder()
                .uuid(uuid)
                .fileName(fileName)
                .post(this)
                .pno(imageSet.size())
                .build();
        imageSet.add(image);
    }

    /**
     * 모든 이미지를 제거하는 메서드
     */
    public void clearAllImages() {
        imageSet.forEach(pPhoto -> pPhoto.changePost(null));
        this.imageSet.clear();
    }

    /**
     * 게시글을 비공개로 설정하는 메서드
     */
    public void setInvisible() {
        this.isVisible = false;
    }

    /**
     * 게시글의 공개 상태를 설정하는 메서드
     *
     * @param isVisible 공개 여부
     */
    public void setIsVisible(boolean isVisible) {
        this.isVisible = isVisible;
    }

    /**
     * 작성자의 username 반환
     *
     * @return 작성자 username
     */
    public String getAuthorUsername() {
        return this.user != null ? this.user.getUsername() : null;
    }
}