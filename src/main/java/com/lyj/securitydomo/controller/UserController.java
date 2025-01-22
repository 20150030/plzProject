package com.lyj.securitydomo.controller;

import com.lyj.securitydomo.config.auth.PrincipalDetails;
import com.lyj.securitydomo.domain.User;
import com.lyj.securitydomo.dto.*;
import com.lyj.securitydomo.repository.UserRepository;
import com.lyj.securitydomo.service.PostService;
import com.lyj.securitydomo.service.RequestService;
import com.lyj.securitydomo.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.modelmapper.ModelMapper;

import java.util.List;


@Log4j2
@Controller
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserService userService;
    private final PostService postService;
    private final ModelMapper modelMapper;
    private final RequestService requestService;

    @PostMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.logout(request, response, SecurityContextHolder.getContext().getAuthentication());
        return "redirect:/"; // 메인 페이지로 리디렉션
    }

    // 회원가입 페이지로 이동
    @GetMapping("/join")
    public void join() {
    }

    /**
     * 회원가입 처리 메서드
     * UserDTO를 받아 비밀번호 암호화 후 저장하고, 이메일을 합쳐서 설정합니다.
     * @param userDTO 회원가입 정보를 담은 UserDTO
     * @param redirectAttributes 리다이렉트 시 전달할 메시지
     * @return 회원가입 후 리다이렉트 페이지
     */
    @PostMapping("/register")
    public String register(UserDTO userDTO, RedirectAttributes redirectAttributes) {
//        log.info("회원가입 진행 : " + userDTO);
        log.info("회원가입 요청 정보: {}", userDTO); // 회원가입 정보 로그 출력

        // 이메일 설정
        userDTO.setEmail(); // emailId와 emailDomain을 합쳐서 email 필드를 설정

        // 비밀번호 암호화
        String rawPassword = userDTO.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        userDTO.setPassword(encPassword); // 암호화된 비밀번호 설정
        userDTO.setRole("USER"); // 기본 권한 설정

        // User 생성 및 저장 (서비스 레이어 사용)
        userService.createUser(userDTO); // 서비스 레이어를 통해 회원가입 처리

        // 회원가입 완료 메시지 추가
        redirectAttributes.addFlashAttribute("message", "회원가입이 완료되었습니다. 로그인 해 주세요.");

        // 회원가입 후 로그인 페이지로 리디렉션
        return "redirect:/user/login"; // 로그인 페이지로 리디렉션
    }

    // 마이페이지 정보 조회
    @GetMapping("/mypage")
    public String getMyPage(@AuthenticationPrincipal PrincipalDetails principal, Model model) {
        log.info("mypage");

        User user = principal.getUser();
        log.info("user: " + user);
        model.addAttribute("user", user);

        return "/user/mypage";
    }

    /**
     * 사용자 정보 수정
     * @param userDTO 수정할 사용자 정보를 담은 UserDTO
     * @return 마이페이지로 리디렉션
     */
    @PostMapping("/update")
    public String updateUser(@ModelAttribute UserDTO userDTO) {
        // 기존 사용자 정보 조회
        User existingUser = userRepository.findById(userDTO.getUserId()).orElseThrow();

        // 이메일 합치기
        userDTO.setEmail();  // emailId와 emailDomain을 합쳐서 email 필드를 설정

        // 비밀번호가 비어있으면 기존 비밀번호 사용, 아니면 새 비밀번호로 암호화 후 설정
        if (userDTO.getPassword() == null || userDTO.getPassword().isEmpty()) {
            userDTO.setPassword(existingUser.getPassword()); // 기존 비밀번호 유지
        } else {
            String encPassword = bCryptPasswordEncoder.encode(userDTO.getPassword()); // 비밀번호 암호화
            userDTO.setPassword(encPassword); // 암호화된 비밀번호로 설정
        }
        userDTO.setRole(existingUser.getRole()); // 기존 권한 유지

        // UserDTO -> User 변환
        User user = modelMapper.map(userDTO, User.class);

        // 수정된 사용자 정보 저장
        userService.save(user);

        return "redirect:/user/mypage"; // 마이페이지로 리디렉션
    }

    // 마이페이지 읽기
    @GetMapping("/readmypage")
    public String readMyPage(Model model, @AuthenticationPrincipal PrincipalDetails principal) {
        return "/user/readmypage";
    }

    /**
     * 사용자 정보 조회
     * @param principal 로그인된 사용자 정보
     * @param model 뷰에 전달할 사용자 정보
     * @return 사용자 정보 페이지
     */
    @GetMapping("/info")
    public String info(@AuthenticationPrincipal PrincipalDetails principal, Model model) {
        model.addAttribute("user", principal.getUser());
        return "/user/info";
    }

    // 회원 탈퇴 기능
    @GetMapping("/delete")
    public String deleteUser(@AuthenticationPrincipal PrincipalDetails principal) {
        User user = principal.getUser();
        userService.deleteUser(user.getUserId()); // 필드명이 userId일 경우
        return "redirect:/user/logout"; // 로그아웃 후 메인 페이지로 이동
    }

    @GetMapping("/mywriting")
    public String redirectToMyPosts(PageRequestDTO pageRequestDTO) {
        // 쿼리 파라미터가 존재하는 경우 유지
        String redirectUrl = String.format("redirect:/posting/user/mywriting?page=%d&size=%d",
                pageRequestDTO.getPage(), pageRequestDTO.getSize());
        return redirectUrl; // 리다이렉트 URL에 쿼리 파라미터 추가
    }
    /**
     * 게시글 읽기 및 수정 페이지를 보여주는 메서드
     */
    @GetMapping("/readwriting/{postId}")
    public String read(@PathVariable Long postId, Model model,
                       @AuthenticationPrincipal PrincipalDetails principal) {
        // 관리자 여부 확인
        boolean isAdmin = "ADMIN".equals(principal.getUser().getRole());

        PostDTO postDTO = postService.readOne(postId,isAdmin);
        log.info(postDTO);
        model.addAttribute("post", postDTO);
        model.addAttribute("originalImages", postDTO.getOriginalImageLinks()); // 이미지 링크 추가
        model.addAttribute("isAuthor", true); // 작성자인 경우
// 작성자 여부 확인
        boolean isAuthor = postDTO.getAuthor().equals(principal.getUser().getUsername());
        model.addAttribute("isAuthor", isAuthor);
        // 신청자리스트 추가 (작성자일 경우에만 조회)
        if (isAuthor) {
            List<RequestDTO> requestList = requestService.getRequestsByPostId(postId);
            model.addAttribute("requestList", requestList);
        }
        return "/posting/read"; // 상세보기 페이지
    }
    @GetMapping("/myapp")
        public String viewMyRequests(Model model, @AuthenticationPrincipal PrincipalDetails principal) {
            if (principal == null) {
                // 인증되지 않은 사용자 처리
                return "redirect:/user/login"; // 로그인 페이지로 리다이렉트
            }

            Long userId = principal.getUser().getUserId();
            List<RequestDTO> requests = requestService.getRequestsByUserId(userId);
            model.addAttribute("requests", requests);
        return "/user/myapp";
    }
}