package com.lyj.securitydomo.controller;

import com.lyj.securitydomo.config.auth.PrincipalDetails;
import com.lyj.securitydomo.domain.Post;
import com.lyj.securitydomo.domain.QPost;
import com.lyj.securitydomo.domain.pPhoto;
import com.lyj.securitydomo.dto.PageRequestDTO;
import com.lyj.securitydomo.dto.PageResponseDTO;
import com.lyj.securitydomo.dto.PostDTO;
import com.lyj.securitydomo.dto.RequestDTO;
import com.lyj.securitydomo.dto.upload.UploadFileDTO;
import com.lyj.securitydomo.dto.upload.UploadResultDTO;
import com.lyj.securitydomo.repository.PostRepository;
import com.lyj.securitydomo.service.PostService;
import com.lyj.securitydomo.service.RequestService;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import net.coobird.thumbnailator.Thumbnailator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import lombok.extern.log4j.Log4j2;

@Controller
@Log4j2
@RequestMapping("/posting")
@RequiredArgsConstructor
public class PostController {

    @Value("${com.lyj.securitydomo.upload.path}")
    private String uploadPath;

    private final PostService postService;
    private final RequestService requestService;
    private final PostRepository postRepository;

    /**
     * 게시글 목록을 조회하고 뷰에 전달하는 메서드
     */
    @GetMapping("/list")
    public String list(PageRequestDTO pageRequestDTO, Model model,
                       @AuthenticationPrincipal PrincipalDetails principal,
                       HttpServletRequest request) {


        log.info("(전체글보기)Received PageRequestDTO: page={}, size={}", pageRequestDTO.getPage(), pageRequestDTO.getSize());
        log.info("Raw HTTP parameters: {}", request.getParameterMap());
        log.info("Query String: {}", request.getQueryString());

        // 기본 페이지 크기 설정
        if (pageRequestDTO.getSize() <= 0) {
            pageRequestDTO.setSize(8);
        }

        // 사용자 역할(관리자 여부) 확인
        boolean isAdmin = principal != null && principal.getUser().getRole().equals("ADMIN");
        model.addAttribute("isAdmin", isAdmin);
        log.info("(컨트롤러)Is Admin: {}", isAdmin); // 관리자 여부 확인 로그



        // 가시성 필터 설정
        pageRequestDTO.setIsVisible(isAdmin ? null : true);
        log.info("(컨트롤러)PageRequestDTO.isVisible: {}", pageRequestDTO.getIsVisible()); // 가시성 필터 확인

        // 게시글 목록 조회
        PageResponseDTO<PostDTO> responseDTO = postService.list(pageRequestDTO, isAdmin);
        responseDTO.getDtoList().forEach(post -> {
            log.info("(컨트롤러) Post Author: {}", post.getAuthor());
        });

        // 작성자인지 여부를 화면에서 판단하기 위해 currentUsername 추가
        if (principal != null) {
            String currentUsername = principal.getUser().getUsername();
            Long currentUserId = principal.getUser().getUserId(); // userId 가져오기

            model.addAttribute("currentUsername", currentUsername);
            model.addAttribute("currentUserId", currentUserId);

            log.info("(컨트롤러) Current Username: {}", currentUsername);
            log.info("(컨트롤러) Current User ID: {}", currentUserId);

        }


        // 데이터 전달
        model.addAttribute("posts", responseDTO.getDtoList());
        model.addAttribute("totalPages", (int) Math.ceil(responseDTO.getTotal() / (double) pageRequestDTO.getSize()));
        model.addAttribute("currentPage", pageRequestDTO.getPage());
        model.addAttribute("baseUrl", "/posting/list"); // 페이징 경로

        log.info("게시글 목록 전달: {}", responseDTO.getDtoList());
        return "posting/list";
    }

    // 내가 쓴 글 보기 메서드 추가
    @GetMapping("/user/mywriting")
    public String myPosts(
            @ModelAttribute PageRequestDTO pageRequestDTO,
            Model model,
            @AuthenticationPrincipal PrincipalDetails principal,
            HttpServletRequest request) {

        // 요청된 HTTP 파라미터 출력 (디버깅용)
        log.info("Raw HTTP parameters: {}", request.getParameterMap());
        log.info("Query String: {}", request.getQueryString());
        log.info("(내글보기) 요청된 PageRequestDTO: page={}, size={}", pageRequestDTO.getPage(), pageRequestDTO.getSize());

        // 인증되지 않은 사용자의 처리 제거
        if (principal == null) {
            log.warn("로그인되지 않은 사용자가 요청을 시도했습니다.");
            return "redirect:/user/login";
        }

        // PageRequestDTO가 비어있는 경우 기본값을 설정
        if (pageRequestDTO.getPage() <= 0) {
            pageRequestDTO.setPage(1); // 기본 페이지는 1
        }
        if (pageRequestDTO.getSize() <= 0) {
            pageRequestDTO.setSize(8); // 기본 사이즈는 8
        }

        log.info("(내글보기) 수정된 PageRequestDTO: page={}, size={}", pageRequestDTO.getPage(), pageRequestDTO.getSize());

        // 현재 로그인된 사용자 확인
        String username = principal.getUser().getUsername();
        log.info("요청한 사용자 이름: {}", username);

        // PostService에서 사용자 게시글 조회
        PageResponseDTO<PostDTO> responseDTO = postService.getPostsByUsername(username, pageRequestDTO);

        // 총 페이지 수 계산
        int totalPages = (int) Math.ceil(responseDTO.getTotal() / (double) pageRequestDTO.getSize());
        log.info("응답 게시글 개수: {}, 총 페이지 수: {}", responseDTO.getDtoList().size(), totalPages);

        // 잘못된 페이지 요청 방지
        if (pageRequestDTO.getPage() > totalPages && totalPages > 0) {
            log.warn("요청한 페이지 번호가 총 페이지 수를 초과했습니다. 마지막 페이지로 리다이렉트합니다.");
            pageRequestDTO.setPage(totalPages); // 마지막 페이지로 수정
            // 리다이렉트가 필요한 경우에만 리다이렉트
            return "redirect:/user/mywriting?page=" + totalPages + "&size=" + pageRequestDTO.getSize();
        }

        // 모델에 데이터 추가
        model.addAttribute("posts", responseDTO.getDtoList()); // 게시글 리스트
        model.addAttribute("currentUsername", username); // 사용자 이름
        model.addAttribute("isAdmin", principal.getUser().getRole().equalsIgnoreCase("ADMIN")); // 관리자 여부
        model.addAttribute("totalPages", totalPages); // 총 페이지 수
        model.addAttribute("currentPage", pageRequestDTO.getPage()); // 현재 페이지 번호
        model.addAttribute("pageSize", pageRequestDTO.getSize()); // 페이지 크기
        model.addAttribute("baseUrl", "/user/mywriting"); // 페이징 URL

        log.info("(내글보기,컨트롤러) 최종 PageRequestDTO: page={}, size={}", pageRequestDTO.getPage(), pageRequestDTO.getSize());

        return "posting/list";
    }
    /**
     * 특정 게시글의 상세 정보를 조회하고 뷰에 전달하는 메서드
     */
    @GetMapping("/read/{postId}")
    public String read(@PathVariable Long postId, Model model,
                       @AuthenticationPrincipal PrincipalDetails principal) {
        String currentUsername = principal.getUser().getUsername();
        Long currentUserId = principal.getUser().getUserId();

        // 관리자 여부 확인
        boolean isAdmin = "ADMIN".equals(principal.getUser().getRole());

        // 게시글 상세 정보 조회 (관리자는 비공개 게시글도 조회 가능)
        PostDTO postDTO = postService.readOne(postId, isAdmin); // isAdmin 매개변수 추가
        model.addAttribute("post", postDTO);
        model.addAttribute("isAdmin", isAdmin);

        // 로그인한 사용자 정보 추가
        model.addAttribute("user", principal.getUser());
        model.addAttribute("currentUsername", currentUsername);
        model.addAttribute("currentUserId", currentUserId);

        // 작성자 여부 확인
        boolean isAuthor = postDTO.getAuthor().equals(currentUsername);
        model.addAttribute("isAuthor", isAuthor);

        // 게시글 공개 상태 추가 (관리자 전용)
        if (isAdmin) {
            model.addAttribute("isVisible", postDTO.isVisible());
        }

        // 신청자리스트 추가 (작성자일 경우에만 조회)
        if (isAuthor) {
            List<RequestDTO> requestList = requestService.getRequestsByPostId(postId);
            model.addAttribute("requestList", requestList);
        }

        // 로그 출력
        log.info("게시글 상세 정보: {}", postDTO);
        log.info("isAdmin: {}, isAuthor: {}", isAdmin, isAuthor);
        log.info("(컨트롤러) Current Username: {}", currentUsername);
        log.info("(컨트롤러) Current User ID: {}", currentUserId);

        return "posting/read";
    }

    /**
     * 게시글 등록 페이지를 보여주는 메서드
     */
    @GetMapping("/register")
    public void registerGET() {
        log.info("게시글 등록 페이지 로드");
    }

    @PostMapping("/register")
    public String registerPost(UploadFileDTO uploadFileDTO,
                               @RequestParam(value = "useRandomImage", required = false, defaultValue = "false") boolean useRandomImage,
                               @Valid PostDTO postDTO, BindingResult bindingResult,
                               RedirectAttributes redirectAttributes) {
        try {
            List<String> fileNames;

            if (useRandomImage) {
                // 랜덤 이미지를 사용
                String randomImage = UploadResultDTO.getRandomImage();
                fileNames = List.of(randomImage);
            } else if (uploadFileDTO.getFiles() != null && !uploadFileDTO.getFiles().isEmpty() &&
                    !uploadFileDTO.getFiles().get(0).getOriginalFilename().isEmpty()) {
                // 파일 업로드 처리
                fileNames = uploadFiles(uploadFileDTO);
            } else {
                // 파일이 없고 랜덤 이미지를 사용하지 않을 경우
                redirectAttributes.addFlashAttribute("error", "이미지가 필요합니다.");
                return "redirect:/posting/register";
            }

            postDTO.setFileNames(fileNames); // 파일 이름 설정
            Long postId = postService.register(postDTO); // 게시글 등록
            redirectAttributes.addFlashAttribute("result", postId); // 등록 성공 알림

            log.info("게시글 등록 성공: ID={}", postId);
        } catch (Exception e) {
            log.error("게시글 등록 오류: {}", e.getMessage());
            redirectAttributes.addFlashAttribute("error", "게시글 등록 중 문제가 발생했습니다.");
            return "redirect:/posting/register";
        }

        return "redirect:/posting/list";
    }
    /**
     * 특정 게시글 수정 페이지를 로드하는 메서드
     */
    @GetMapping("/modify/{postId}")
    public String modify(@PathVariable Long postId, Model model,
                         @AuthenticationPrincipal PrincipalDetails principal) {
        String currentUsername = principal.getUser().getUsername();
        boolean isAdmin = "ADMIN".equals(principal.getUser().getRole());

        // 게시글 정보 조회 (관리자는 비공개 게시글도 조회 가능)
        PostDTO postDTO = postService.readOne(postId, isAdmin);
        if (!isAdmin && !postDTO.getAuthor().equals(currentUsername)) {
            throw new AccessDeniedException("수정 권한이 없습니다.");
        }

        model.addAttribute("post", postDTO);
        model.addAttribute("originalImages", postDTO.getOriginalImageLinks());

        log.info("수정할 게시글 정보: {}", postDTO);
        return "posting/modify";
    }

    @PostMapping("/modify/{postId}")
    public String modifyPost(@PathVariable Long postId, PageRequestDTO pageRequestDTO, UploadFileDTO uploadFileDTO,
                             @Valid PostDTO postDTO, BindingResult bindingResult, RedirectAttributes redirectAttributes,
                             @AuthenticationPrincipal PrincipalDetails principal) {
        if (bindingResult.hasErrors()) {
            redirectAttributes.addFlashAttribute("errors", bindingResult.getAllErrors());
            redirectAttributes.addAttribute("postId", postDTO.getPostId());
            return "redirect:/posting/modify/" + postId;
        }

        String currentUsername = principal.getUser().getUsername();
        boolean isAdmin = "ADMIN".equals(principal.getUser().getRole());

        // 작성자 또는 관리자 권한 확인
        PostDTO existingPost = postService.readOne(postId, isAdmin);
        if (!isAdmin && !existingPost.getAuthor().equals(currentUsername)) {
            throw new AccessDeniedException("수정 권한이 없습니다.");
        }

        try {
            List<String> fileNames = uploadFileDTO.getFiles() != null && !uploadFileDTO.getFiles().isEmpty() &&
                    !uploadFileDTO.getFiles().get(0).getOriginalFilename().isEmpty()
                    ? uploadFiles(uploadFileDTO) // 새 파일 업로드
                    : existingPost.getFileNames(); // 기존 파일 유지

            postDTO.setFileNames(fileNames); // 파일 설정
            postService.modify(postDTO); // 게시글 수정 서비스 호출
            redirectAttributes.addFlashAttribute("result", "modified");

            log.info("게시글 수정 성공: ID={}", postId);
        } catch (IOException e) {
            redirectAttributes.addFlashAttribute("error", "이미지 파일 처리 중 문제가 발생했습니다.");
            log.error("게시글 수정 중 오류: {}", e.getMessage());
        }

        redirectAttributes.addAttribute("postId", postDTO.getPostId());
        return "redirect:/posting/read/{postId}";
    }

    /**
     * 게시글 삭제 처리 메서드
     */
    @GetMapping("/remove/{postId}")
    public String remove(@PathVariable Long postId, RedirectAttributes redirectAttributes) {
        postService.remove(postId);
        redirectAttributes.addFlashAttribute("result", "removed");
        log.info("게시글 삭제 성공: ID={}", postId);
        return "redirect:/posting/list";
    }

    /**
     * 게시글 비공개 처리 메서드
     * - 관리자가 신고된 게시글을 비공개로 처리
     */
    @PostMapping("/hide/{postId}")
    public String markPostAsInvisible(@PathVariable Long postId, RedirectAttributes redirectAttributes) {
        try {
            postService.makePostInvisible(postId);
            redirectAttributes.addFlashAttribute("message", "게시글이 비공개 처리되었습니다.");
            log.info("게시글 비공개 처리 완료: postId={}", postId); // 추가된 로그 메시지
        } catch (EntityNotFoundException e) {
            redirectAttributes.addFlashAttribute("error", "해당 게시글을 찾을 수 없습니다.");
            log.error("게시글 비공개 처리 중 오류: postId={}, error={}", postId, e.getMessage()); // 추가된 오류 로그

        }
        return "redirect:/posting/list";
    }

    /**
     * 게시글 공개 처리 메서드
     * - 관리자가 비공개 상태의 게시글을 다시 공개 처리
     */
    @PostMapping("/show/{postId}")
    public String markPostAsVisible(@PathVariable Long postId, RedirectAttributes redirectAttributes) {
        try {
            postService.makePostVisible(postId); //게시글 공개 처리
            redirectAttributes.addFlashAttribute("message", "게시글이 공개 처리되었습니다.");
            log.info("게시글 공개 처리 완료: postId={}", postId); // 추가된 로그 메시지

        } catch (EntityNotFoundException e) {
            redirectAttributes.addFlashAttribute("error", "해당 게시글을 찾을 수 없습니다.");
            log.error("게시글 공개 처리 중 오류: postId={}, error={}", postId, e.getMessage()); // 추가된 오류 로그

        }
        return "redirect:/posting/list";
    }

    private List<String> uploadFiles(UploadFileDTO uploadFileDTO) throws IOException {
        List<String> fileNames = new ArrayList<>();

        for (MultipartFile file : uploadFileDTO.getFiles()) {
            String originalName = file.getOriginalFilename(); // 원본 파일 이름
            if (originalName == null || originalName.isEmpty()) {
                log.warn("빈 파일 이름이 감지되었습니다. 파일 처리 건너뜀.");
                continue;
            }

            String uuid = UUID.randomUUID().toString(); // 고유 식별자 생성
            Path savePath = Paths.get(uploadPath, uuid + "_" + originalName);

            try {
                // 파일 저장
                file.transferTo(savePath);
                log.info("파일 저장 성공: {}", savePath);

                // 이미지 포맷 검증 및 썸네일 생성
                try {
                    File thumbnail = new File(uploadPath, "s_" + uuid + "_" + originalName);
                    log.info("썸네일 생성 시도: {}", savePath);
                    Thumbnailator.createThumbnail(savePath.toFile(), thumbnail, 200, 200);
                    log.info("썸네일 생성 성공: {}", thumbnail.getAbsolutePath());

                    // 파일 이름 추가
                    fileNames.add("s_" + uuid + "_" + originalName); // 썸네일 파일 이름
                    fileNames.add(uuid + "_" + originalName);       // 원본 파일 이름
                } catch (IOException e) {
                    log.warn("썸네일 생성 실패: {}", e.getMessage());
                    throw new IOException("유효하지 않은 이미지 파일입니다: " + originalName, e);
                }
            } catch (IOException e) {
                log.error("파일 저장 중 오류 발생: {}", e.getMessage(), e);
                throw e;
            }
        }

        log.info("업로드 처리 완료. 저장된 파일 수: {}", fileNames.size());
        return fileNames;
    }
}