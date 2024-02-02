package com.tech.kj;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

@Component
public class JwtFilter extends OncePerRequestFilter {
    Logger log = LoggerFactory.getLogger(JwtFilter.class);
    private final JwtTokenProvider jwtTokenUtil;
    @Value("${jwt.header.string}")
    public String HEADER_STRING;

    @Value("${jwt.token.prefix}")
    public String TOKEN_PREFIX;

    @Value("${application.security.jwt.secret-key}")
    private String SIGNING_KEY;

    @Value("${jwt.authorities.key}")
    public String AUTHORITIES_KEY;

    public JwtFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenUtil = jwtTokenProvider;
        //this.userDetailsService = userDetailsService;
    }

    public static boolean matchPattern(String url, String pattern) {
        if (pattern.endsWith("/**")) {
            String prefix = pattern.substring(0, pattern.length() - 3);
            return url.startsWith(prefix);
        } else {
            return url.equals(pattern);
        }
    }
    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String requestedUri = request.getServletPath();
        log.info("filtering requested URI: {}",requestedUri);
        //if(request.getServletPath().contains("/api/v1/auth"))
        for(String whiteListUri: CommonConstant.WHITE_LIST_URL){
            if(matchPattern(requestedUri,whiteListUri)){
                filterChain.doFilter(request, response);
                return;
            }
        }
        String header = request.getHeader(HEADER_STRING);
        String username = null;
        Claims claims = null;
        String authToken = null;
        if (header != null && header.startsWith(TOKEN_PREFIX)) {
            authToken = header.replace(TOKEN_PREFIX, "").trim();
            try {
                username = jwtTokenUtil.getUsernameFromToken(authToken);
                claims =jwtTokenUtil.getAllClaimsFromToken(authToken);

                log.info("username:{} and claims: {} from token: {}",username,claims,authToken);
            } catch (IllegalArgumentException e) {
                log.error("An error occurred while fetching Username from Token", e);
            } catch (ExpiredJwtException e) {
                log.warn("The token has expired", e);
            } catch (SignatureException e) {
                log.error("Authentication Failed. Username or Password not valid.");
            }
        } else {
            log.warn("Couldn't find bearer string, header will be ignored");
        }
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            final Collection<? extends GrantedAuthority> authorities =
                    Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList());

            UserDetails userDetails = new User(username, "", authorities);
            if (jwtTokenUtil.isValidSignature(authToken, SIGNING_KEY) && !jwtTokenUtil.isTokenExpired(authToken)) {
                UsernamePasswordAuthenticationToken authentication = jwtTokenUtil.getAuthenticationToken(authToken, SecurityContextHolder.getContext().getAuthentication(), userDetails);
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                log.info("authenticated user " + username + ", setting security context");
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        filterChain.doFilter(request, response);
    }
}
