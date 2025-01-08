package com.lyj.securitydomo.service;

import com.lyj.securitydomo.domain.Report;
import com.lyj.securitydomo.dto.ReportDTO;

import java.util.List;

/**
 * ReportService 인터페이스
 * 신고 기능과 관련된 서비스 레이어의 동작을 정의합니다.
 */
public interface ReportService {

    /**
     * 새로운 신고를 생성합니다.
     *
     * @param reportDTO 신고 데이터 전달 객체
     */
    void createReport(ReportDTO reportDTO);

    /**
     * 모든 신고를 조회합니다.
     *
     * @return ReportDTO 리스트 (각 게시글의 신고 횟수를 포함)
     */
    List<ReportDTO> getAllReports();

    /**
     * 진행 중인 신고(PENDING 상태)를 조회합니다.
     *
     * @return 진행 중인 ReportDTO 리스트
     */
    List<ReportDTO> getReportsInProgress();

    /**
     * 특정 게시글(postId)에 대한 신고를 조회합니다.
     *
     * @param postId 게시글 ID
     * @return 특정 게시글에 대한 ReportDTO 리스트
     */
    List<ReportDTO> getReportsByPostId(Long postId);

    /**
     * 특정 신고(reportId)의 상태를 공개(VISIBLE)로 변경합니다.
     *
     * @param reportId 신고 ID
     */
    void markAsVisible(Long reportId);

    /**
     * 특정 신고(reportId)의 상태를 비공개(HIDDEN)로 변경합니다.
     *
     * @param reportId 신고 ID
     */
    void markAsHidden(Long reportId);

    /**
     * 신고 ID로 게시글 ID를 반환합니다.
     *
     * @param reportId 신고 ID
     * @return 해당 신고와 관련된 게시글의 ID
     */
    Long getPostIdByReportId(Long reportId);

    /**
     * 중복 신고를 제거하고 신고 건수를 합산하여 반환합니다.
     *
     * @param onlyVisible true이면 공개된 글만 포함, false이면 전체 글 포함
     * @return 중복 신고가 제거된 신고 리스트
     */
    List<ReportDTO> getUniqueReportsWithCounts(Boolean onlyVisible);
}