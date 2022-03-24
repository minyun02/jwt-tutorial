package com.jwt.jwttutorial.service;

import java.util.Collections;
import java.util.Optional;

import com.jwt.jwttutorial.dto.UserDto;
import com.jwt.jwttutorial.entity.Authority;
import com.jwt.jwttutorial.entity.User;
import com.jwt.jwttutorial.exception.DuplicateMemberException;
import com.jwt.jwttutorial.repository.UserRepository;
import com.jwt.jwttutorial.util.SecurityUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public UserDto signup(UserDto userDto) {
        /*
        username이 db에 존재하지 않으면 Authority와 User 정보를 생성해서
        UserRepository의 save 메소드를 통해 db에 저장

        중요한 점은 signup 메소드를 통해 가입한 회원은 USER ROLE을 가지고 있다
        data.sql에서 자동 생성한 admin은 USER, ADMIN ROLE을 가지고 있다.
         */
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            throw new DuplicateMemberException("이미 가입되어 있는 유저입니다.");
        }

        Authority authority = Authority.builder()
                .authorityName("ROLE_USER")
                .build();

        User user = User.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();

        return UserDto.from(userRepository.save(user));
    }

    @Transactional(readOnly = true)
    public UserDto getUserWithAuthorities(String username) {
        /*
        유저, 권한정보를 가져오는 메소드
        username을 기준으로 정보를 가져온다.
         */
        return UserDto.from(userRepository.findOneWithAuthoritiesByUsername(username).orElse(null));
    }

    @Transactional(readOnly = true)
    public UserDto getMyUserWithAuthorities() {
        /*
        SecurityContext에 저장된 username의 정보만 가져온다.
         */
        return UserDto.from(SecurityUtil.getCurrentUsername().flatMap(userRepository::findOneWithAuthoritiesByUsername).orElse(null));
    }
}
