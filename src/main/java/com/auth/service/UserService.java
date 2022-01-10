package com.auth.service;

import com.auth.model.UserDetails;
import com.auth.payload.request.LoginRequest;
import com.auth.payload.request.SignupRequest;
import com.auth.payload.response.JwtResponse;
import com.auth.payload.response.MessageResponse;
import org.springframework.http.ResponseEntity;

public interface UserService {

    public JwtResponse authenticateService(LoginRequest loginRequest);

    public MessageResponse registerService(SignupRequest signUpRequest);

    boolean requestPasswordReset(String email);

    Boolean generateOtp(String username);
}
