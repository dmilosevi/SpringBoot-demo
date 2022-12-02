package com.example.demo.service;

import java.util.List;

import com.example.demo.models.AppUser;
import com.example.demo.models.Role;

public interface AppUserService {
	AppUser saveUser(AppUser user);
	Role saveRole(Role role);
	void addRoleToUser(String username, String roleName);
	AppUser getUser(String username);
	List<AppUser> getUsers();
}
