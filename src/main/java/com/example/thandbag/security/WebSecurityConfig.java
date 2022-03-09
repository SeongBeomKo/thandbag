package com.example.thandbag.security;

import com.auth0.jwt.JWT;
import com.example.thandbag.security.filter.JwtAuthFilter;
import com.example.thandbag.security.jwt.HeaderTokenExtractor;
import com.example.thandbag.security.provider.JWTAuthProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.ArrayList;
import java.util.List;


@Configuration
@RequiredArgsConstructor
@EnableWebSecurity // 스프링 Security 지원을 가능하게 함
@EnableGlobalMethodSecurity(securedEnabled = true) // @Secured 어노테이션 활성화
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final JWTAuthProvider jwtAuthProvider;
    private final HeaderTokenExtractor headerTokenExtractor;

    @Bean
    public BCryptPasswordEncoder encodePassword() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .authenticationProvider(jwtAuthProvider); // CustomAuthenticationProvider()를 호출하기 위해서 Overriding
    }

    @Override
    public void configure(WebSecurity web) {
        web
                .ignoring()
                .antMatchers("/favicon.ico")
                .antMatchers("/profile")
                .antMatchers("/h2-console/**"); //H2-Console 허용
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/api/user/signup").permitAll()
                .antMatchers("/api/user/login").permitAll()
                .antMatchers("/h2-console/**").permitAll()
                .antMatchers("/chat/**").permitAll()
                .antMatchers("/chat/room/**").permitAll()
                .antMatchers("/sub/chat/room/**").permitAll()
                .antMatchers("/pub/chat/room/**").permitAll()
                .antMatchers("/ws-stomp/sub/chat/room/**").permitAll()
                .antMatchers("/ws-stomp/pub/chat/room/**").permitAll()
                .antMatchers("/ws-stompAlarm/**").permitAll()
                .antMatchers("/ws-stompAlarm/sub/alarm/**").permitAll()
                .antMatchers("**/pub/chat/room/**").permitAll()
                .antMatchers("**/sub/chat/room/**").permitAll()
                .antMatchers("/profile").permitAll()
                .antMatchers(
                        "/v2/api-docs",
                        "/swagger-resources/**",
                        "**/swagger-resources/**",
                        "/swagger-ui.html",
                        "/webjars/**",
                        "/swagger/**",
                        "/configuration/ui",
                        "/configuration/security",
                        "/health"
                ).permitAll()
                .and()
                .authorizeRequests()
                .antMatchers("/chat/**").hasRole("USER") // chat으로 시작하는 리소스에 대한 접근 권한 설정
                .anyRequest().permitAll()
                .and()
                .exceptionHandling();

        http
                .csrf()
                .disable()
                .cors()
                .configurationSource(corsConfigurationSource())// 기본값이 on인 csrf 취약점 보안을 해제한다. on으로 설정해도 되나 설정할경우 웹페이지에서 추가처리가 필요함.
                .and()
                .headers()
                .frameOptions().sameOrigin(); // SockJS는 기본적으로 HTML iframe 요소를 통한 전송을 허용하지 않도록 설정되는데 해당 내용을 해제한다.

        http // 서버에서 인증은 JWT로 인증하기 때문에 Session의 생성을 막습니다.
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http
                .addFilterBefore(jwtFilter(), UsernamePasswordAuthenticationFilter.class);

        http // NginX
                .requiresChannel()
                .antMatchers("/")
                .requiresSecure();
    }

    /* JwtFilter : 서버에 접근시 JWT 확인 후 인증을 실시합니다. */
    private JwtAuthFilter jwtFilter() throws Exception {
        List<String> skipPathList = new ArrayList<>();

        // 회원 관리 API 허용
        skipPathList.add("POST,/api/user/signup");
        skipPathList.add("POST,/api/user/login");
        skipPathList.add("GET,/user/kakao/callback");
        skipPathList.add("POST,/user/kakao/callback");
        // h2-console 허용
        skipPathList.add("GET,/h2-console/**");
        skipPathList.add("POST,/h2-console/**");
        // Swagger 허용
        skipPathList.add("GET,/swagger-ui.html");
        skipPathList.add("GET,/swagger/**");
        skipPathList.add("GET,/swagger-resources/**");
        skipPathList.add("GET,/webjars/**");
        skipPathList.add("GET,/v2/api-docs");
        skipPathList.add("GET,configuration/ui");
        skipPathList.add("GET,/configuration/security");
        skipPathList.add("GET,/health");
        skipPathList.add("GET,/profile");
        // 기본 허용 사항들
        skipPathList.add("GET,/");
        skipPathList.add("GET,/favicon.ico");
        // 채팅
        skipPathList.add("GET,/chat/room/**");
        skipPathList.add("GET,/sub/chat/room/**");
        skipPathList.add("GET,/pub/chat/room/**");
        skipPathList.add("GET,/ws-stomp/pub/chat/room/**");
        skipPathList.add("GET,/ws-stompAlarm/pub/chat/room/**");
        skipPathList.add("GET,**/pub/chat/room/**");
        skipPathList.add("GET,**/sub/chat/room/**");
        skipPathList.add("GET,/ws-stomp/**");
        skipPathList.add("GET,/ws-stompAlarm/**");
        skipPathList.add("GET,/ws-stompAlarm/sub/alarm/**");
        //게시글 조회/ 상세 조회
        skipPathList.add("GET,/api/thandbagList");
        skipPathList.add("GET,/api/thandbag");
        skipPathList.add("GET,/api/visitor/thandbag/**");
        skipPathList.add("POST,/mypage/profileTest");

        FilterSkipMatcher matcher = new FilterSkipMatcher(
                skipPathList,
                "/**"
        );

        JwtAuthFilter filter = new JwtAuthFilter(
                matcher,
                headerTokenExtractor
        );
        filter.setAuthenticationManager(super.authenticationManagerBean());

        return filter;
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOrigin("http://thandbag.com.s3-website.ap-northeast-2.amazonaws.com");
        configuration.setAllowCredentials(true);
        configuration.addAllowedMethod("*");
        configuration.addAllowedHeader("*");
        configuration.addExposedHeader("Authorization");
        configuration.addAllowedOriginPattern("*");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}