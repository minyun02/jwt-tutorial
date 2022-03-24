package com.jwt.jwttutorial.controller;

import com.jwt.jwttutorial.dto.LoginDto;
import com.jwt.jwttutorial.dto.TokenDto;
import com.jwt.jwttutorial.jwt.JwtFilter;
import com.jwt.jwttutorial.jwt.TokenProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping("/api")
public class AuthController {
    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public AuthController(TokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.tokenProvider = tokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    @PostMapping("/authenticate")
    /*
    loginDto의 username, password를 파라미터로 받고
    이를 이용해 UsernamePasswordAuthenticationToekn을 생성
    authenticationToken을 이용해서 Authentication 객체를 생성하려고 authenticate메소드가 실행 될때 loadUserByUsername 메소드가 실행
    이 결과값을 가지고 Authentication 객체를 생성하고 이를 SecurityContext에 저장하고
    Authentication 객체를 createToken메소드를 통해서 Jwt Token을 생성
    jwt Token을 Response Header에도 넣어주고
    TokenDto를 이용해서 Response Body에도 넣어서 리턴
     */
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto) {

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = tokenProvider.createToken(authentication);

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);

        return new ResponseEntity<>(new TokenDto(jwt), httpHeaders, HttpStatus.OK);
    }
}
