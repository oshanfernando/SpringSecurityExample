package com.example.demoapp.service;

import com.example.demoapp.entity.Role;
import com.example.demoapp.enums.ERole;
import com.example.demoapp.repository.RoleRepository;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class InitData {
    private final RoleRepository repo;

    public InitData(RoleRepository repo) {
        this.repo = repo;
    }

    @EventListener
    public void appReady(ApplicationReadyEvent event) {
        Role r1 = new Role(ERole.ROLE_USER);
        Role r2 = new Role(ERole.ROLE_ADMIN);

        repo.saveAll(List.of(r1, r2));
    }
}

