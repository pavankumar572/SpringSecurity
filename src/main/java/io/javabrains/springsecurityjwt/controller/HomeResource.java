package io.javabrains.springsecurityjwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.javabrains.springsecurityjwt.MyUserDetailsService;
import io.javabrains.springsecurityjwt.model.AuthenticationRequest;
import io.javabrains.springsecurityjwt.model.AuthenticationResponse;
import io.javabrains.springsecurityjwt.utils.JwtUtil;

@RestController
public class HomeResource {

	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	JwtUtil util;

	@Autowired
	MyUserDetailsService userDetailsService;

	@RequestMapping("/hello")
	public String home() {
		return "Welcome Home";
	}

	@PostMapping("/authenticate")
	public ResponseEntity<?> getJWT(@RequestBody AuthenticationRequest request) throws Exception {
		try {
			authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(request.getUserName(), request.getPassword()));

		} catch (BadCredentialsException e) {
			throw new Exception("Invalid username or password");
		}
		final UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUserName());
		final String jwt = util.generateToken(userDetails);
		return ResponseEntity.ok(new AuthenticationResponse(jwt));
	}

}
