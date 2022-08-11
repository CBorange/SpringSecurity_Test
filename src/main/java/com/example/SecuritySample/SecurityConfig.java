package com.example.SecuritySample;
import com.example.SecuritySample.model.JwtAuthenticationFilter;
import com.example.SecuritySample.model.JwtTokenProvider;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig{

    private final JwtTokenProvider jwtTokenProvider;

    // 인증과정이 무시되는 Static Resource 리스트
    private static final String[] AUTH_STATIC_RESOURCES = {
            "/image/**",
            "/file/**"
    };

    // 회원가입 시 password 암호화 처리하는 PasswordEncoder Bean 설정
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    // Spring Security FilterChain 설정 Bean(WebSecurityConfigurerAdapter depercate 됨에따라 대체)
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http){
        try {
            http.csrf().disable();

            // Statefull Session 연결 시 사용(기본 인증)
            /*http.authorizeRequests()
            // login 없이 접근허용 하는 url
            .antMatchers("/auth/**").permitAll()
            // ADMIN 권한이 있는 경우 접근할 수 있는 url
            .antMatchers("/admin").hasRole("ADMIN")
            // 그 외 모든 요청은 인증이 필요
            .anyRequest().authenticated();*/

            // Stateless JWT(토큰) 인증 시 사용
            http.authorizeRequests()
            // login 없이 접근허용 하는 url
            .antMatchers("/auth/**").permitAll()
            // ADMIN 권한이 있는 경우 접근할 수 있는 url
            .antMatchers("/admin").hasRole("ADMIN")
            // 그 외 모든 요청은 인증이 필요
            .anyRequest().authenticated()
            .and()
            // 토큰 기반 인증이기 때문에 session을 사용하지 않도록 설정
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            // JwtAuthenticationFilter는 UsernamePasswordAuthenticationFilter 전에 넣음
            .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider),
                    UsernamePasswordAuthenticationFilter.class);

            return http.build();
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Generate SecurityFilterChain Fail : " + e.getMessage());
            return null;
        }
    }

    // 정적 리소스에 대한 인증을 무시하도록 하는 설정
    @Bean
    public WebSecurityCustomizer ignoringCustomizer(){
        return (web) -> web.ignoring().antMatchers(AUTH_STATIC_RESOURCES);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}