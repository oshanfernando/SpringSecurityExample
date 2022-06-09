package com.example.demoapp.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;


@Controller
public class ViewController {

    @GetMapping("/login")
    public String showLogin() {
        return "login-page";
    }


}
