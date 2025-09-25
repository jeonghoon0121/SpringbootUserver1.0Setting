package com.ohgiraffers.sessionsecurity.auth.model.sevice;

import com.ohgiraffers.sessionsecurity.auth.model.AuthDetails;
import com.ohgiraffers.sessionsecurity.user.model.dto.LoginUserDTO;
import com.ohgiraffers.sessionsecurity.user.model.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Objects;

/* security에서 사용자의 아이디를 인증하기 위한 인터페이스이다.
*  loadUserByUsername을 필수로 구현해야 하며 로그인 인증 시 해당 메소드에
*  login 요청 시 전달된 사용자의 id를 매개변수로 DB에서 조회한다.
* */
@Service
public class AuthService implements UserDetailsService {

    @Autowired
    private UserService userService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        LoginUserDTO login = userService.findByUsername(username);

        if(Objects.isNull(login)) {
            throw new UsernameNotFoundException("해당하는 회원 정보가 존재하지 않습니다.");
        }

        return new AuthDetails(login);
    }
}
