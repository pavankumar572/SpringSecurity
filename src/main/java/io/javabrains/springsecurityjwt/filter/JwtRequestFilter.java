package io.javabrains.springsecurityjwt.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.javabrains.springsecurityjwt.MyUserDetailsService;
import io.javabrains.springsecurityjwt.utils.JwtUtil;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

	@Autowired
	private MyUserDetailsService service;

	@Autowired
	private JwtUtil util;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		 final String authHeader= request.getHeader("Authorization");
		 
		 String  userName= null;
		 String jwt=null;
		 if(authHeader!=null && authHeader.startsWith("Bearer ")) {
			 jwt=authHeader.substring(7);
			 userName= util.extractUsername(jwt);
		 }
		 if(userName!=null && SecurityContextHolder.getContext().getAuthentication() == null) {
			 UserDetails details = this.service.loadUserByUsername(userName);
			 if(util.validateToken(jwt, details)) {
				 UsernamePasswordAuthenticationToken token= 
						 new UsernamePasswordAuthenticationToken(details, null,details.getAuthorities());
				 token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				 SecurityContextHolder.getContext().setAuthentication(token);
			 }
		 }
		 filterChain.doFilter(request, response);
	}

}
