package com.example.demoapp.controller;

import com.example.demoapp.model.AuthSuccessDTO;
import com.example.demoapp.model.LoginDTO;
import com.example.demoapp.model.SignupDTO;
import com.example.demoapp.service.UserService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;


@Controller
@CrossOrigin(origins = "*", maxAge = 3600)
public class ViewController {
    private final UserService userService;

    public ViewController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping(value = "/login")
    public String showLogin(Model model, @RequestParam(value = "message", required = false) String message) {
        model.addAttribute("loginDTO", new LoginDTO());
        if (StringUtils.hasText(message)) {
            model.addAttribute("message", message);
        }
        return "login-page";
    }

    @PostMapping("/login")
    public String loginUser(@ModelAttribute LoginDTO loginDTO, Model model) {
        AuthSuccessDTO authSuccessDTO = userService.loginUser(loginDTO);
        model.addAttribute("response", authSuccessDTO);
        return "result";
    }

    @GetMapping("/register")
    public String showRegisterForm(Model model) {
        model.addAttribute("signupDTO", new SignupDTO());
        return "register-form";
    }

    @PostMapping("/register")
    public String registerUser(@ModelAttribute SignupDTO signupDTO) {
        userService.saveUser(signupDTO);
        return "redirect:/login?message=Registration success!! Please login";
    }


}
