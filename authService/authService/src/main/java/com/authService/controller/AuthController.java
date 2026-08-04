package com.authService.controller;

import com.authService.entity.APIResponse;
import com.authService.entity.User;
import com.authService.payload.LoginDto;
import com.authService.payload.UserDto;
import com.authService.repository.UserRepository;
import com.authService.service.AuthService;
import com.authService.service.JwtService;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private AuthService authService;
    private AuthenticationManager authenticationManager;
    private JwtService jwtService;
    private UserRepository userRepository;

    public AuthController(AuthService authService, AuthenticationManager authenticationManager, JwtService jwtService, UserRepository userRepository) {
        this.authService = authService;
        this.authenticationManager = authenticationManager;

        this.jwtService = jwtService;
        this.userRepository = userRepository;
    }

    @PostMapping("/register")
    public ResponseEntity<APIResponse<String>> register(@RequestBody UserDto dto){
        APIResponse<String> register = authService.register(dto);
        return new ResponseEntity<>(register, HttpStatusCode.valueOf(register.getStatus()));
    }

    @PostMapping("/login")
    public ResponseEntity<APIResponse<String>> login(@RequestBody LoginDto dto){

        APIResponse<String> response=new APIResponse<>();

        UsernamePasswordAuthenticationToken token=new UsernamePasswordAuthenticationToken(dto.getUsername(),dto.getPassword());

        try {
            Authentication authenticate = authenticationManager.authenticate(token);
            if (authenticate.isAuthenticated()){

                String jwtToken = jwtService.generateToken(dto.getUsername(), authenticate.getAuthorities().iterator().next().getAuthority());

                response.setMessage("Login Successful");
                response.setStatus(200);
                response.setData(jwtToken);
                return new ResponseEntity<>(response,HttpStatusCode.valueOf(response.getStatus()));
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        response.setMessage("Failes");
        response.setStatus(401);
        response.setData("Un-Authorized Access");
        return new ResponseEntity<>(response,HttpStatusCode.valueOf(response.getStatus()));
    }

    @GetMapping("/get-user")
    public User getUserByUsername(@RequestParam String username){
        User user = userRepository.findByUsername(username);
        return user;
    }
}
