package com.cos.security1.config.auth;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
//로그인 진행이 완료가 되면 시큐리티 Session을 만들어 줌.(Security ContextHolder)
// 오브젝트 타입 -> Authentication 타입 객체
//Authentication 안에 User 정보가 있어야 함.
//User 오브젝트 타입 => UserDetails 타입 객체

//Security Session => Authentication(PrincipalDetailsService) => UserDetail(PrincipalDetails)

// UserDetailsService(PrincipalDetailsService) 가 Authentication 객체 역할

//시큐리티 요청에서 loginProcessUrl("/login"); (SecurityConfig 클래스)
// /login 요청이 오면 자동으로 UserDetailService 타입으로 IoC 되어 있는 loadUserByUsername 함수가 실행됨

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    // 여기서 parameter 인 username은 POST /login 요청의 username 파라미터에 매핑
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = userRepository.findByUsername(username);
        if (userEntity != null) {
            //리턴된 값은
            //시큐리티 Session(내부 Authentication(내부 UserDetails))
            return new PrincipalDetails(userEntity);
        }
        return null;
    }
}
