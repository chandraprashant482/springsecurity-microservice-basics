package com.authService.service;

import com.authService.entity.APIResponse;
import com.authService.entity.User;
import com.authService.payload.UserDto;
import com.authService.repository.UserRepository;
import org.springframework.beans.BeanUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;

    APIResponse<String> response=new APIResponse<>();

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public APIResponse<String> register(UserDto userDto){
        if (userRepository.existsByUsername(userDto.getUsername())){
            response.setMessage("Registration Failed");
            response.setStatus(500);
            response.setData("UserName Already Taken");
            return response;
        }
        if (userRepository.existsByEmail(userDto.getEmail())){
            response.setMessage("Registration Failed");
            response.setStatus(500);
            response.setData("Email Already Registered");
            return response;
        }

        String encode = passwordEncoder.encode(userDto.getPassword());
        User user=new User();
        BeanUtils.copyProperties(userDto,user);
        user.setPassword(encode);
        user.setRole("ROLE_ADMIN");
        User savedUser = userRepository.save(user);

        if (savedUser==null){

        }
        response.setMessage("Registration Completed");
        response.setStatus(201);
        response.setData("User Has Been Registered");
        return response;
    }
}
