
package com.lyj.securitydomo.service;

import com.lyj.securitydomo.domain.Post;
import com.lyj.securitydomo.domain.User;
import com.lyj.securitydomo.domain.QUser;
import com.lyj.securitydomo.domain.pPhoto;
import com.lyj.securitydomo.dto.PageRequestDTO;
import com.lyj.securitydomo.dto.PageResponseDTO;
import com.lyj.securitydomo.dto.PostDTO;
import com.lyj.securitydomo.dto.upload.UploadResultDTO;
import com.lyj.securitydomo.repository.PostRepository;
import com.lyj.securitydomo.repository.ReplyRepository;
import com.lyj.securitydomo.repository.ReportRepository;
import com.lyj.securitydomo.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

import static com.lyj.securitydomo.domain.QPost.post;

//import static com.lyj.securitydomo.domain.QUser.user;


@Service
@Log4j2
@Transactional
@RequiredArgsConstructor
public class PostServiceImpl implements PostService {
    @Value("${com.lyj.securitydomo.upload.path}")
    private String uploadPath;
    private Boolean isVisible; // 게시글의 가시성 필터 추가 (null: 모든 게시글, true: 공개, false: 비공개)
    private final UserRepository userRepository;
    private final PostRepository postRepository;
    private final ReportRepository reportRepository;
    private final ReplyRepository replyRepository;


    /**
     * Post 엔티티를 PostDTO로 변환하는 유틸리티 메서드
     * - 중복되는 변환 로직을 재사용하기 위해 분리
     *
     * @param post Post 엔티티
     * @return PostDTO
     */
    private PostDTO convertToDTO(Post post) {
        // Null-safe 이미지 파일 처리
        List<String> fileNames = post.getImageSet() != null
                ? post.getImageSet().stream()
                .map(image -> image.getUuid() + "_" + image.getFileName())
                .collect(Collectors.toList())
                : Collections.emptyList();

        List<String> originalImageLinks = post.getImageSet() != null
                ? post.getImageSet().stream()
                .map(pPhoto::getOriginalLink)
                .collect(Collectors.toList())
                : Collections.emptyList();

        // 댓글 수 가져오기
        int replyCount = replyRepository.countByPostId(post.getPostId());
        // DTO 빌더로 변환
        return PostDTO.builder()
                .postId(post.getPostId()) // 게시글 ID
                .title(post.getTitle()) // 제목
                .contentText(post.getContentText()) // 본문 내용
                .createdAt(post.getCreatedAt()) // 등록 날짜
                .updatedAt(post.getUpDatedAt()) // 수정 날짜
                .fileNames(fileNames) // 이미지 파일 이름 목록
                .originalImageLinks(originalImageLinks) // 원본 이미지 링크 목록
                .thumbnailLink(getThumbnailLink(post)) // 썸네일 링크
                .requiredParticipants(post.getRequiredParticipants()) // 모집 인원
                .status(post.getStatus() != null ? post.getStatus().name() : null) // 모집 상태
                .author(post.getUser() != null ? post.getUser().getUsername() : null) // 작성자
                .lat(post.getLat()) // 위도
                .lng(post.getLng()) // 경도
                .firstComeFirstServe(post.isFirstComeFirstServe()) // 선착순 여부
                .deadline(post.getDeadline()) // 모집 마감 기한
                .isVisible(post.isVisible()) // 공개 여부
                .replyCount(replyCount) // 댓글 수
                .reportCount(replyCount)//신고 수
                .build();
    }

    /**
     * 썸네일 링크를 반환하는 메서드
     * - 파일이 존재하면 첫 번째 파일의 썸네일 링크를 반환
     * - 파일이 없으면 랜덤 이미지를 반환
     *
     * @param post Post 엔티티
     * @return 썸네일 링크
     */
    private String getThumbnailLink(Post post) {
        if (post.getImageSet() != null && !post.getImageSet().isEmpty()) {
            // 파일이 있는 경우 첫 번째 이미지의 썸네일 링크 반환
            pPhoto firstImage = post.getImageSet().iterator().next();
            //log.info("썸네일 생성 - UUID: {}, FileName: {}", firstImage.getUuid(), firstImage.getFileName());
            return "/view/s_" + firstImage.getUuid() + "_" + firstImage.getFileName();
        }
        // 파일이 없는 경우 랜덤 이미지 반환
        String randomImage = UploadResultDTO.getRandomImage();
        //log.info("썸네일 생성 - 랜덤 이미지: {}", randomImage);
        return randomImage;
    }

    @Override
    public Long register(PostDTO postDTO) {
        // 현재 인증된 사용자 정보 가져오기
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new IllegalArgumentException("사용자가 인증되지 않았습니다.");
        }
        String username = authentication.getName();
        log.info("현재 로그인된 사용자 이름: {}", username);

        // 사용자 찾기
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("해당 사용자를 찾을 수 없습니다."));

        // Post 엔티티 생성
        Post post = Post.builder()
                .title(postDTO.getTitle())
                .contentText(postDTO.getContentText())
                .user(user)
                .requiredParticipants(postDTO.getRequiredParticipants())
                .status(postDTO.getStatus() != null ? Post.Status.valueOf(postDTO.getStatus()) : Post.Status.모집중)
                .lat(postDTO.getLat())
                .lng(postDTO.getLng())
                .firstComeFirstServe(postDTO.isFirstComeFirstServe())
                .deadline(postDTO.getDeadline())
                .build();

        log.info("게시글 생성 중: {}", post);

        // 파일 정보 추가
        if (postDTO.getFileNames() != null && !postDTO.getFileNames().isEmpty()) {
            postDTO.getFileNames().forEach(fileName -> {
                if (fileName.startsWith("s_")) {
                    // 썸네일 이름에서 원본 파일 UUID 및 이름 추출
                    String[] split = fileName.substring(2).split("_", 2); // 's_' 이후 부분 사용
                    if (split.length == 2) {
                        post.addImage(split[0], split[1]);
                        log.info("이미지 추가 - UUID: {}, FileName: {}", split[0], split[1]);
                    } else {
                        log.warn("썸네일 파일 이름 형식이 잘못되었습니다: {}", fileName);
                    }
                } else {
                    log.warn("파일 이름이 썸네일 형식을 따르지 않습니다: {}", fileName);
                }
            });
        } else {
            // 파일이 없을 경우 랜덤 이미지 추가
            String randomImageUrl = UploadResultDTO.getRandomImage();
            String randomImageName = randomImageUrl.substring(randomImageUrl.lastIndexOf("/") + 1);
            post.addImage("random-" + UUID.randomUUID(), randomImageName);
            log.info("파일이 없어서 랜덤 이미지를 사용합니다: {}", randomImageUrl);
        }

        // Post 엔티티 저장
        Long postId = postRepository.save(post).getPostId();
        log.info("게시글이 성공적으로 등록되었습니다. ID: {}", postId);

        return postId;
    }


    /**
     * 게시글 단건 조회 메서드
     * - 비공개된 게시글은 조회 불가
     *
     * @param postId 조회할 게시글의 ID
     * @return 조회된 게시글의 DTO
     */
    @Override
    public PostDTO readOne(Long postId,Boolean isAdmin) {
        Post post = postRepository.findById(postId)
                .filter(postEntity -> isAdmin || postEntity.isVisible())
                .orElseThrow(() -> new EntityNotFoundException("게시글을 찾을 수 없거나 비공개 상태입니다."));

        return convertToDTO(post); // 엔티티를 DTO로 변환하여 반환
    }

    /**
     * 게시글 수정 메서드
     * - 작성자만 수정 가능
     * - 엔티티 메서드에 의존하지 않고 직접 필드 수정
     */

    @Override
    public void modify(PostDTO postDTO) {
        // 게시글 조회
        Post post = postRepository.findById(postDTO.getPostId())
                .orElseThrow(() -> new EntityNotFoundException("게시글을 찾을 수 없습니다."));

        // 작성자 검증
        String currentUsername = SecurityContextHolder.getContext().getAuthentication().getName();
        if (!post.getUser().getUsername().equals(currentUsername)) {
            throw new IllegalStateException("작성자만 게시글을 수정할 수 있습니다.");
        }

        // 필드 업데이트
        if (postDTO.getTitle() != null && !postDTO.getTitle().trim().isEmpty()) {
            post.setTitle(postDTO.getTitle());
        }
        if (postDTO.getContentText() != null && !postDTO.getContentText().trim().isEmpty()) {
            post.setContentText(postDTO.getContentText());
        }
        if (postDTO.getRequiredParticipants() != null && postDTO.getRequiredParticipants() > 0) {
            post.setRequiredParticipants(postDTO.getRequiredParticipants());
        }
        if (postDTO.getStatus() != null) {
            post.setStatus(Post.Status.valueOf(postDTO.getStatus()));
        }

        // 유효 범위로 체크 (예: 위도와 경도의 기본값이 0.0일 경우)
        if (postDTO.getLat() != 0.0) {
            post.setLat(postDTO.getLat());
        } else {
            log.info("위도 값이 기본값이므로 기존 값을 유지합니다.");
        }

        if (postDTO.getLng() != 0.0) {
            post.setLng(postDTO.getLng());
        } else {
            log.info("경도 값이 기본값이므로 기존 값을 유지합니다.");
        }

        // 선착순 여부 수정
        post.setFirstComeFirstServe(postDTO.isFirstComeFirstServe());

        // 마감일 수정
        if (postDTO.getDeadline() != null) {
            if (postDTO.getDeadline().before(new Date())) {
                throw new IllegalArgumentException("마감일은 현재 날짜보다 이후여야 합니다.");
            }
            post.setDeadline(postDTO.getDeadline());
        }

        // 변경된 게시글 저장
        postRepository.save(post);

        // 로그 출력
        log.info("게시글 수정 완료: ID={}", post.getPostId());
    }

    //파일삭제
    private void removeFile(List<String> fileNames) {
        for (String fileName : fileNames) {
            try {
                Path filePath = Paths.get(uploadPath, fileName);
                Files.deleteIfExists(filePath); // 원본 파일 삭제
                log.info("Deleted file: " + filePath);

                // 썸네일 이미지 삭제 (s_ prefix가 있는 파일로 가정)
                Path thumbnailPath = Paths.get(uploadPath, "s_" + fileName);
                Files.deleteIfExists(thumbnailPath); // 썸네일 파일 삭제
                log.info("Deleted thumbnail: " + thumbnailPath);

            } catch (IOException e) {
                log.error("Error deleting file: " + fileName, e);
            }
        }
    }

    //삭제
    @Override
    public void remove(Long postId) {
        Optional<Post> postOptional = postRepository.findById(postId);

        if (postOptional.isPresent()) {
            Post post = postOptional.get();

            // 이미지 파일 삭제
            List<String> fileNames = post.getOriginalImageLinks();
            if (fileNames != null && !fileNames.isEmpty()) {
                removeFile(fileNames);
            }

            // 이미지 연관 관계 제거
            post.clearAllImages();

            log.info("=============="+postId);
            // 게시글 삭제
            postRepository.deleteById(postId);
            log.info("Deleted post with ID: " + postId);
        } else {
            log.warn("Post with ID " + postId + " does not exist.");
        }
    }


    /**
     * 게시글 목록 조회 메서드
     * - 페이징 및 검색 조건 포함
     *
     * @param pageRequestDTO 페이징 요청 정보
     * @return 페이징된 게시글 DTO 목록
     */
    @Override
    public PageResponseDTO<PostDTO> list(PageRequestDTO pageRequestDTO, boolean isAdmin) {
        Pageable pageable = pageRequestDTO.getPageable("postId");

        // 가시성 필터 설정: 관리자는 null(모든 게시글), 일반 사용자는 true(공개된 게시글만)
        Boolean isVisible = isAdmin ? null : true;
        pageRequestDTO.setIsVisible(isVisible); // PageRequestDTO에도 필터 값을 반영

        log.info("PostServiceImpl - 전체 글 보기 요청 처리 시작");
        log.info("사용자 타입 (관리자 여부): {}", isAdmin ? "관리자" : "일반 사용자");
        log.info("isVisible 필터: {}", isVisible);

        // 레포지토리 검색
        Page<Post> result = postRepository.searchAll(
                pageRequestDTO.getTypes(),
                pageRequestDTO.getKeyword(),
                pageable,
                isVisible // 가시성 필터 적용
        );
        log.info("레포지토리에서 반환된 게시글: {}", result.getContent());
        // Post 엔티티를 PostDTO로 변환
        List<PostDTO> dtoList = result.getContent().stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());

        log.info("검색 결과: 총 {}개의 게시글 조회됨", result.getTotalElements());

        return PageResponseDTO.<PostDTO>withAll()
                .pageRequestDTO(pageRequestDTO) // 요청 정보 포함
                .dtoList(dtoList) // 변환된 DTO 리스트
                .total((int) result.getTotalElements()) // 총 게시글 수
                .build();
    }



    @Override
    public PageResponseDTO<PostDTO> getPostsByUsername(String username, PageRequestDTO pageRequestDTO) {
        Pageable pageable = pageRequestDTO.getPageable("createdAt"); // 최신순 정렬

        log.info("(서비스) Pageable 생성 결과 - Page: {}, Size: {}", pageable.getPageNumber(), pageable.getPageSize());

        log.info("(서비스)getPostsByUsername(내 글 보기) - 요청 처리 시작");
        log.info("(서비스)Pageable 정보 - Page: {}, Size: {}", pageable.getPageNumber(), pageable.getPageSize());
        log.info("(서비스)Username: {}", username);


        // 작성자 이름으로 게시글 조회
        Page<Post> result = postRepository.findByUsername(username, pageable);

        log.info("레포지토리에서 반환된 게시글 개수: {}", result.getContent().size());
        log.info("레포지토리에서 반환된 총 게시글 수: {}", result.getTotalElements());


        // Post 엔티티 -> PostDTO 변환
        List<PostDTO> dtoList = result.getContent().stream()
                .map(this::convertToDTO) // 기존 convertToDTO 메서드 활용
                .collect(Collectors.toList());

        // PageResponseDTO 생성 및 반환
        return PageResponseDTO.<PostDTO>withAll()
                .pageRequestDTO(pageRequestDTO) // 요청 정보 포함
                .dtoList(dtoList) // 변환된 DTO 리스트
                .total((int) result.getTotalElements()) // 총 게시글 수
                .build();
    }
    /**
     * 게시글 비공개 처리 메서드
     * - 게시글을 비공개(isVisible=false) 상태로 변경
     *
     * @param postId 비공개 처리할 게시글 ID
     */
    @Override
    public void makePostInvisible(Long postId) {
        Post post = postRepository.findById(postId)
                .orElseThrow(() -> new EntityNotFoundException("해당 게시글을 찾을 수 없습니다."));
        post.setIsVisible(false); // 게시글을 비공개로 설정
        postRepository.save(post); // 변경 사항 저장

        log.info("게시글이 비공개 처리되었습니다. ID: {}, 제목: {}", postId, post.getTitle());
    }

    /**
     * 게시글 공개 처리 메서드
     * - 게시글을 공개(isVisible=true) 상태로 변경
     *
     * @param postId 공개 처리할 게시글 ID
     */
    @Override
    public void makePostVisible(Long postId) {
        Post post = postRepository.findById(postId)
                .orElseThrow(() -> new EntityNotFoundException("해당 게시글을 찾을 수 없습니다."));
        post.setIsVisible(true); // 게시글을 공개로 설정
        postRepository.save(post); // 변경 사항 저장

        log.info("게시글이 공개 처리되었습니다. ID: {}, 제목: {}", postId, post.getTitle());
    }

    /**
     * 게시글 조회 및 검증 메서드
     * - 게시글 ID를 통해 게시글을 조회하고 존재하지 않을 경우 예외 처리
     *
     * @param postId 조회할 게시글 ID
     * @return Post 엔티티
     */
    private Post getPostById(Long postId) {
        return postRepository.findById(postId)
                .orElseThrow(() -> new EntityNotFoundException("게시글을 찾을 수 없습니다. ID: " + postId));
    }



}
