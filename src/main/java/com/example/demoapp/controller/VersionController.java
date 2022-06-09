package com.example.demoapp.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/version")
public class VersionController {

    @Value("${app.version}")
    private String appVersion;

    @GetMapping()
    public String getVersion() {
        return appVersion;
    }
}
