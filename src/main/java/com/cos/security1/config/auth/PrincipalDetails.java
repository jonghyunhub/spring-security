package com.cos.security1.config.auth;
import com.cos.security1.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;


// 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
//로그인 진행이 완료가 되면 시큐리티 Session을 만들어 줌.(Security ContextHolder)
// 오브젝트 타입 -> Authentication 타입 객체
//Authentication 안에 User 정보가 있어야 함.
//User 오브젝트 타입 => UserDetails 타입 객체

//Security Session => Authentication => UserDetail(PrincipalDetails)

@Data
public class PrincipalDetails implements UserDetails {

    private User user;

    public PrincipalDetails(User user) {
        this.user = user;
    }

    //해당 User의 권한을 리턴하는 곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {

            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {

        // 1년동안 회원이 로그인을 안하면 휴면계정으로 전환
        //user 엔티티에 private Timestamp loginDate; 만들고
        //현재시간 - 로그인 시간 => 1년이 넘으면 리턴 false 해주면 됨

        return true;
    }
}
