package com.example.SecuritySample.service;

import com.example.SecuritySample.domain.Member;
import com.example.SecuritySample.dto.JwtRequestDto;
import com.example.SecuritySample.dto.JwtResponseDto;
import com.example.SecuritySample.dto.MemberSignupRequestDto;
import com.example.SecuritySample.model.JwtTokenProvider;
import com.example.SecuritySample.model.UserDetailsImpl;
import com.example.SecuritySample.repository.MemberRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@AllArgsConstructor
public class AuthService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

    public String login_session(JwtRequestDto request) {
        Authentication authentication = authenticationManager.authenticate(
          new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl principal = (UserDetailsImpl)authentication.getPrincipal();
        return principal.getUsername();
    }

    public JwtResponseDto login(JwtRequestDto request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        return createJwtToken(authentication);
    }

    private JwtResponseDto createJwtToken(Authentication authentication){
        UserDetailsImpl principal = (UserDetailsImpl) authentication.getPrincipal();
        String token = jwtTokenProvider.generateToken(principal);
        return new JwtResponseDto(token);
    }

    public String signup(MemberSignupRequestDto request){
        boolean existMember = memberRepository.existsById(request.getEmail());

        // 기등록된 회원 email인 경우
        if(existMember) return null;

        // 정상 접근
        Member member = new Member(request);
        member.encryptPassword(passwordEncoder);

        memberRepository.save(member);
        return member.getEmail();
    }
}
