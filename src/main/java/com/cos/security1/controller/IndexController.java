package com.cos.security1.controller;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller //"view를 리턴하겠다"
@RequiredArgsConstructor
public class IndexController {

    private final UserRepository userRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping({"", "/"})
    public String index() {
        return "index";
    }

    @GetMapping("/user")
    public @ResponseBody
    String user() {
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody
    String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody
    String manager() {
        return "manager";
    }

    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        user.setRole("ROLE_USER");
        //시큐리티는 비밀번호 암호화를 안하면 로그인이 안되기때문에 비밀번호 암호화가 필수
        String rawPassword = user.getPassword();
        String encPassowrd = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassowrd);
        userRepository.save(user);
        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info() {
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')") //함수가 시작하기 전에 권한 여러개 걸고싶을때 사용
//    @PostAuthorize() 함수가 끝나고 나서 권한 설정 해주는 에너테이션 but PreAuthorize 많이 쓰지 PostAuthorize 쓸일은 거의 없다.
    @GetMapping("/data")
    public @ResponseBody String data() {
        return "데이터정보";
    }
}
