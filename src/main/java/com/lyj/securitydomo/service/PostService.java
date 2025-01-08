
package com.lyj.securitydomo.service;

import com.lyj.securitydomo.domain.Post;
import com.lyj.securitydomo.domain.User;
import com.lyj.securitydomo.dto.PageRequestDTO;
import com.lyj.securitydomo.dto.PageResponseDTO;
import com.lyj.securitydomo.dto.PostDTO;

import java.util.List;

public interface PostService {

    // 게시글 등록
    Long register(PostDTO postDTO);

    // 게시글 상세 조회
    PostDTO readOne(Long postId,Boolean isAdmin);

    // 게시글 수정
    void modify(PostDTO postDTO);

    // 게시글 삭제
    void remove(Long postId);

    // 게시글 목록 조회
    PageResponseDTO<PostDTO> list(PageRequestDTO pageRequestDTO, boolean isAdmin);

    // 게시글 비공개 처리
    void makePostInvisible(Long postId);

    // 게시글 공개 처리
    void makePostVisible(Long postId);

    // 작성자가 쓴 게시글 목록 (DTO 반환)
    PageResponseDTO<PostDTO> getPostsByUsername(String username, PageRequestDTO pageRequestDTO);


}
