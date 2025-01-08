package com.lyj.securitydomo.repository;

import com.lyj.securitydomo.domain.Post;
import com.lyj.securitydomo.domain.Report;
import com.lyj.securitydomo.domain.User;
import com.lyj.securitydomo.dto.ReportDTO;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface ReportRepository extends JpaRepository<Report, Long> {

    /**
     * 모든 신고 목록 조회
     *
     * @return 모든 Report 엔티티 리스트
     */
    List<Report> findAll();

    /**
     * 특정 상태(PENDING, HIDDEN, VISIBLE 등)에 해당하는 신고 목록 조회
     *
     * @param status 신고 상태
     * @return 해당 상태의 Report 엔티티 리스트
     */
    List<Report> findByStatus(Report.ReportStatus status);
    // 비공개 상태가 아닌 글만 조회
    @Query("SELECT r FROM Report r WHERE r.status = 'PENDING' AND r.post.isVisible = true")
    List<Report> findPendingAndVisibleReports();
    /**
     * 특정 게시글(postId)에 대한 모든 신고 목록 조회
     *
     * @param postId 게시글 ID
     * @return 특정 게시글에 대한 Report 엔티티 리스트
     */
    List<Report> findByPost_PostId(Long postId);

    /**
     * 특정 게시글과 사용자의 조합으로 중복 신고 여부 확인
     *
     * @param post 게시글 엔티티
     * @param user 사용자 엔티티
     * @return 중복 신고 여부 (true/false)
     */
    boolean existsByPostAndUser(Post post, User user);

    /**
     * 특정 게시글에 대한 신고 건수 조회
     *
     * @param postId 게시글 ID
     * @return 신고 건수
     */
    @Query("SELECT COUNT(r) FROM Report r WHERE r.post.postId = :postId")
    int countReportsByPostId(@Param("postId") Long postId);

    /**
     * 특정 게시글(postId)의 상태를 비공개/공개 처리
     *
     * @param postId 게시글 ID
     * @param status 업데이트할 상태 (VISIBLE/HIDDEN)
     */
    @Modifying
    @Query("UPDATE Report r SET r.status = :status WHERE r.post.postId = :postId")
    void updateStatusByPostId(@Param("postId") Long postId, @Param("status") Report.ReportStatus status);

}