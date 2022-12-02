//prva stvar koju zelimo je "uvesti" repozitorije (AppUserRepo i RoleRepo) jer oni komunicijraju direktno s JPA (kreiraju query-e umjesto nas)

//@RequiredArgsConstructor
//Lombok ce kreirati konstruktor i pobrinuti se da su svi argumenti (userRepo, roleRepo) proslijedeni u kontrusktor
//ovo je zapravo DEPENDENCY INJECTION

//@Transactional
//uvijek ide u SERVICE LAYER

//@Slf4j 
//za loggove - jer cemo zapisivati sve sto se bude dogadalo
package com.example.demo.service;

import java.util.List;

import javax.transaction.Transactional;

import org.springframework.stereotype.Service;

import com.example.demo.models.AppUser;
import com.example.demo.models.Role;
import com.example.demo.repo.AppUserRepo;
import com.example.demo.repo.RoleRepo;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Transactional //zelimo da sve u klasi bude Transactional
@Slf4j
public class AppUserServiceImpl implements AppUserService {
	

	private final AppUserRepo userRepo;
	private final RoleRepo roleRepo;
	
	@Override
	public AppUser saveUser(AppUser user) {
		log.info("Saving new user {} to the database", user.getUsername());
		return userRepo.save(user);
	}

	@Override
	public Role saveRole(Role role) {
		log.info("Saving new role {} to the database", role.getName());
		return roleRepo.save(role);
	}

	@Override
	public void addRoleToUser(String username, String roleName) {
		log.info("Adding role {} to user {}", roleName, username);
		AppUser user = userRepo.findByUsername(username); //prvo moramo pronaci Usera po username
		Role role = roleRepo.findByName(roleName); //zatim pronademo Role po roleName
		//sada kada imamo Usera(AppUser) i Role zelimo dodati Role na Usera (AppUser)
		//.getRoles() je getter metoda koja nije vildjiva jer koristimo Lombok
		//prvo dobivamo sve Roles od tog usera i zatim dodajemo taj role na sve ostale koje vec ima do sada
		user.getRoles().add(role);
	}//kada se ova metoda zavrsi spremit ce se sve u bazu podataka automatski zbog anotacije @Transaction 
		//ne moramo zvati AppUserRepo i zatim ponovno spremiti

	@Override
	public AppUser getUser(String username) {
		log.info("Fetching user {}", username);
		return userRepo.findByUsername(username); //
	}

	@Override
	public List<AppUser> getUsers() {
		log.info("Fetching all users");
		return userRepo.findAll();
	}

}
