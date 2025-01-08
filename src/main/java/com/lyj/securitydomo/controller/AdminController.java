package com.lyj.securitydomo.controller;

import com.lyj.securitydomo.dto.ReportDTO;
import com.lyj.securitydomo.dto.UserDTO;
import com.lyj.securitydomo.service.PostService;
import com.lyj.securitydomo.service.ReportService;
import com.lyj.securitydomo.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/admin")
@Log4j2
@RequiredArgsConstructor
public class AdminController {

    private final UserService userService;
    private final ReportService reportService;
    private final PostService postService;

    /**
     * 관리자 메인 페이지
     */
    @GetMapping("/adminIndex")
    public String adminIndex() {
        log.info("관리자 메인 페이지 요청");
        return "admin/adminIndex";
    }

    /**
     * 신고 목록 조회
     */
    @GetMapping("/reports")
    public String getReports(
            @RequestParam(value = "filter", defaultValue = "all") String filter, Model model) {
        log.info("신고 목록 조회 요청, filter: {}", filter);

        // 필터 설정
        Boolean onlyVisible = "visible".equalsIgnoreCase(filter);

        // 중복 신고 합산 및 필터 처리
        List<ReportDTO> reportList = reportService.getUniqueReportsWithCounts(onlyVisible);

        // 모델에 데이터 추가
        model.addAttribute("reportList", reportList);
        model.addAttribute("filter", filter); // 현재 필터 값을 프론트엔드에 전달

        return "admin/reportList"; // 신고 리스트 페이지로 이동
    }

    /**
     * 특정 게시글의 신고 조회
     */
    @GetMapping("/reports/post/{postId}")
    public String getReportsByPostId(@PathVariable Long postId, Model model) {
        log.info("특정 게시글의 신고 조회 요청, postId: {}", postId);

        List<ReportDTO> reports = reportService.getReportsByPostId(postId);

        model.addAttribute("reports", reports);
        model.addAttribute("postId", postId);

        return "admin/reportsByPost"; // 특정 게시글 신고 리스트 페이지로 이동
    }

    /**
     * 신고 상태 토글 처리 (비공개/공개)
     */
    @PostMapping("/reports/{reportId}/toggle-visibility")
    @ResponseBody
    public String toggleVisibility(@PathVariable Long reportId, @RequestBody Map<String, Boolean> requestBody) {
        log.info("신고 상태 토글 요청, reportId: {}", reportId);

        // 요청에서 visible 값 확인
        boolean visible = requestBody.getOrDefault("visible", false);

        // 상태에 따라 처리
        if (visible) {
            log.info("신고 공개 처리: reportId={}", reportId);
            reportService.markAsVisible(reportId);
            Long postId = reportService.getPostIdByReportId(reportId);
            postService.makePostVisible(postId);
        } else {
            log.info("신고 비공개 처리: reportId={}", reportId);
            reportService.markAsHidden(reportId);
            Long postId = reportService.getPostIdByReportId(reportId);
            postService.makePostInvisible(postId);
        }

        return visible ? "게시글이 공개 처리되었습니다." : "게시글이 비공개 처리되었습니다.";
    }

    /**
     * 모든 사용자 목록 조회
     */
    @GetMapping("/users")
    public String getAllUsers(Model model) {
        log.info("모든 사용자 목록 조회 요청");

        // 모든 사용자 조회
        List<UserDTO> userList = userService.getAllUsers();

        log.info("조회된 사용자 수: {}", userList.size()); // 사용자 수를 로깅
        userList.forEach(user -> log.info("사용자 정보: {}", user)); // 각 사용자 정보 로깅

        model.addAttribute("userList", userList);

        return "admin/users"; // 사용자 리스트 페이지로 이동
    }

    /**
     * 사용자 강퇴
     */
    @PostMapping("/users/{userId}/ban")
    @ResponseBody
    public String banUser(@PathVariable Long userId) {
        log.info("회원 강퇴 요청: userId={}", userId);

        try {
            userService.adminDeleteUser(userId); // UserService를 통해 회원 삭제
            log.info("회원 강퇴 성공: userId={}", userId);
            return "사용자가 성공적으로 강퇴되었습니다.";
        } catch (Exception e) {
            log.error("회원 강퇴 실패: userId={}, error={}", userId, e.getMessage());
            return "강퇴 중 오류가 발생했습니다. 다시 시도해주세요.";
        }
    }
}