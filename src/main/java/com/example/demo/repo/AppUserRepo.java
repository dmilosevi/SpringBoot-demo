package com.example.demo.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.demo.models.AppUser;

public interface AppUserRepo extends JpaRepository<AppUser, Long> {
	AppUser findByUsername(String username);
}
