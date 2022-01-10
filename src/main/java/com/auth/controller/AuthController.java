package com.auth.controller;

import com.auth.payload.request.LoginRequest;
import com.auth.payload.request.SignupRequest;
import com.auth.payload.response.*;
import com.auth.repository.RoleRepository;
import com.auth.repository.UserRepository;
import com.auth.payload.request.PasswordResetRequestModel;
import com.auth.security.jwt.JwtUtils;
import com.auth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    UserService userService;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        JwtResponse userDetails = userService.authenticateService(loginRequest);

        return ResponseEntity.ok(userDetails);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {

     MessageResponse messageResponse = userService.registerService(signUpRequest);

        return ResponseEntity.ok(messageResponse);
    }

    @PostMapping("/password-reset-request")
    public OperationStatusModel requestReset(@RequestBody PasswordResetRequestModel passwordResetRequestModel){
        OperationStatusModel returnValue = new OperationStatusModel();

        boolean operationResult = userService.requestPasswordReset(passwordResetRequestModel.getEmail());

        returnValue.setOperationName(RequestOperationName.REQUEST_PASSWORD_RESET.name());
        returnValue.setOperationResult(RequestOperationStatus.ERROR.name());

        if (operationResult){
            returnValue.setOperationResult(RequestOperationStatus.SUCCESS.name());
        }

        return returnValue;

    }


    @PostMapping("/generate-otp")
    public ResponseEntity<Object> generateOTP()
    {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();

        Map<String, String> response = new HashMap<>(2);

        // check authentication
        if (username == null) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }

        // generate OTP.
        Boolean isGenerated = userService.generateOtp(username);
        if (!isGenerated)
        {
            response.put("status", "error");
            response.put("message", "OTP can not be generated.");

            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }

        // success message
        response.put("status", "success");
        response.put("message", "OTP successfully generated. Please check your e-mail!");

        return new ResponseEntity<>(response, HttpStatus.OK);
    }


    @PostMapping("/forgot-password")
    public void forgotPassword(){

    }



}
