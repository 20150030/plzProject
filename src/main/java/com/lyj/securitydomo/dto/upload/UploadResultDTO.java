package com.lyj.securitydomo.dto.upload;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Random;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UploadResultDTO {

    private String uuid;
    private String fileName;
    private int pno;

    /**
     * 썸네일 이미지 링크를 반환하는 메서드
     * @return 썸네일 이미지 링크
     */
    public String getThumbnailLink() {
        return (uuid != null && fileName != null)
                ? "/view/s_" + uuid + "_" + fileName  // 썸네일 파일명으로 생성
                : getRandomImage(); // 썸네일 이미지가 없으면 랜덤 이미지 반환
    }

    /**
     * 원본 이미지 링크를 반환하는 메서드
     * @return 원본 이미지 링크
     */
    public String getOriginalLink() {
        return (uuid != null && fileName != null)
                ? "/view/" + uuid + "_" + fileName // 원본 파일명으로 생성
                : getRandomImage();
    }

    /**
     * 기본 랜덤 이미지를 반환하는 메서드
     * 업로드된 이미지가 없는 경우 호출됩니다.
     *
     * @return 기본 랜덤 이미지 링크
     */
    public static String getRandomImage() {
        String[] defaultImages = {
                "https://cdn.blueconomy.co.kr/news/photo/202402/2399_3001_921.png",
                "https://i.namu.wiki/i/gYcA1HTcdvXbMbun0_63Ix0tuxPrDwioIiEUj78aG0h2d2KCpOb120QN4Mru_SbPgD0L_jrYBprE0yg8b_-6Vw8ZoSLNcf3gKj8Ti93FUVjXbdba0SYumsNC19zXnUMh2xl2HRCr0ms1oX3ABMLIvQ.webp",
                "https://cdn.sisaweek.com/news/photo/202004/132716_121857_70.jpg"
        };
        Random random = new Random();
        return defaultImages[random.nextInt(defaultImages.length)];
    }
}