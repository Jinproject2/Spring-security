package me.whiteship.demospringsecurityform.config;

import me.whiteship.demospringsecurityform.account.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    AccountService accountService;

    public SecurityExpressionHandler expressionHandler() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");

        DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);

        return handler;
    }


    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
        //web.ignoring().mvcMatchers("/favicon.ico");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .mvcMatchers("/", "/info", "/account/**", "/signup").permitAll()
                .mvcMatchers("/admin").hasRole("ADMIN")
                .mvcMatchers("/user").hasRole("USER")
                //.requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                .anyRequest().authenticated()
                .expressionHandler(expressionHandler());
        http.formLogin()
            .loginPage("/login")
            .permitAll();

        http.rememberMe()
                .userDetailsService(accountService)
                .key("remember-me-sample");

        http.httpBasic();

        http.logout().logoutSuccessUrl("/");

        //maximumSessions 설정에 따라 로그인은 한 개의 사용자(브라우저)에서만 가능하게 설정이 가능하며, true일 경우 먼저 로그인한 사용자 우선 false(default) 일 경우 기존 사용자 로그아웃
        http.sessionManagement()
                .sessionFixation()
                    .changeSessionId()
                .maximumSessions(1)
                    .maxSessionsPreventsLogin(false);

        // TODO ExceptionTranslatorFilter -> FilterSecurityInterceptor (AccessDecisionManager, AffirmativeBased)
        // TODO AuthenticationException -> AuthenticationEntryPoint
        // TODO AccessDinedException -> AccessDeniedHandler

        //http.exceptionHandling().accessDeniedPage("/access-denied");
        http.exceptionHandling()
            .accessDeniedHandler((httpServletRequest, httpServletResponse, e) -> {
                UserDetails principal = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
                String username = principal.getUsername();
                System.out.println(username + " is denied to access " + httpServletRequest.getRequestURI());
                httpServletResponse.sendRedirect("/access-denied");
            });

        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    }
}
