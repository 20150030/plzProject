package com.lyj.securitydomo.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

@Getter
@ToString
public class PageResponseDTO<E> {
    private int page; // 현재 페이지
    private int size; // 페이지 크기
    private int total; // 전체 데이터 수

    private int start; // 시작 페이지 번호
    private int end; // 끝 페이지 번호
    private boolean prev; // 이전 페이지 존재 여부
    private boolean next; // 다음 페이지 존재 여부

    private List<E> dtoList; // DTO 리스트

    @Builder(builderMethodName = "withAll")
    public PageResponseDTO(PageRequestDTO pageRequestDTO, List<E> dtoList, int total) {
        this.page = pageRequestDTO.getPage();
        this.size = pageRequestDTO.getSize();
        this.total = total;

        // dtoList가 null인 경우 빈 리스트로 초기화
        this.dtoList = dtoList != null ? dtoList : new ArrayList<>();

        if (total <= 0) {
            this.start = 0;
            this.end = 0;
            this.prev = false;
            this.next = false;
            return; // 데이터가 없으면 기본값으로 설정 후 리턴
        }

        // 시작 및 끝 페이지 번호 계산
        this.end = (int) (Math.ceil(this.page / 10.0)) * 10; // 화면에서의 끝 페이지
        this.start = this.end - 9; // 화면에서의 시작 페이지

        int last = (int) (Math.ceil((double) total / size)); // 데이터 개수를 기반으로 한 마지막 페이지

        this.end = Math.min(end, last); // 끝 페이지 수정
        this.prev = this.start > 1; // 이전 페이지 존재 여부
        this.next = total > this.end * this.size; // 다음 페이지 존재 여부
    }
}