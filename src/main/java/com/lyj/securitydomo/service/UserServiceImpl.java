// UserServiceImpl.java
package com.lyj.securitydomo.service;

import com.lyj.securitydomo.domain.User;
import com.lyj.securitydomo.dto.UserDTO;
import com.lyj.securitydomo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Log4j2
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final ModelMapper modelMapper;

    @Transactional
    @Override
    public UserDTO createUser(UserDTO userDTO) {
        User user = modelMapper.map(userDTO, User.class);
        User savedUser = userRepository.save(user);
        return modelMapper.map(savedUser, UserDTO.class);
    }

    @Override
    public UserDTO getUserById(Long userId) {
        return userRepository.findById(userId)
                .map(user -> modelMapper.map(user, UserDTO.class))
                .orElseThrow(() -> new UsernameNotFoundException("User not found with ID: " + userId));
    }

    //관리자
    @Override
    public List<UserDTO> getAllUsers() {
        List<User> users = userRepository.findAll();
        log.info("UserRepository에서 조회된 사용자 수: {}", users.size()); // 조회된 사용자 수 로깅

        return users.stream()
                .map(user -> {
                    UserDTO userDTO = modelMapper.map(user, UserDTO.class);
                    log.info("User를 UserDTO로 매핑: {}", userDTO); // 매핑된 DTO 로깅
                    return userDTO;
                })
                .collect(Collectors.toList());
    }

    @Override
    public User getCurrentUser() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Current user not found"));
    }

    @Override
    @Transactional
    public void updateUser(Long userId, UserDTO userDTO) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with ID: " + userId));
        user.setEmail(userDTO.getEmail());
        user.setCity(userDTO.getCity());
        user.setState(userDTO.getState());
        user.setBirthDate(userDTO.getBirthDate());
        userRepository.save(user);
    }

    @Override
    public void deleteUser(Long id) {
        userRepository.deleteById(id);
    }

    /**
     * 관리자에 의한 회원 강퇴 기능
     * @param userId 강퇴할 사용자 ID
     */
    @Override
    public void adminDeleteUser(Long userId) {
        deleteUser(userId);
    }

    @Override
    public void save(User user) {
        userRepository.save(user);
    }
    @Override
    public User findByUsername(String username) {
        return null;
    }
}