//prva stvar koju zelimo je "uvesti" repozitorije (AppUserRepo i RoleRepo) jer oni komunicijraju direktno s JPA (kreiraju query-e umjesto nas)

//@RequiredArgsConstructor
//Lombok ce kreirati konstruktor i pobrinuti se da su svi argumenti (userRepo, roleRepo) proslijedeni u kontrusktor
//ovo je zapravo DEPENDENCY INJECTION

//@Transactional
//uvijek ide u SERVICE LAYER

//@Slf4j 
//za loggove - jer cemo zapisivati sve sto se bude dogadalo

//public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
//Ovo je metoda koju moramo Override-ati nakon sto smo implementirali UserDetailsService
//to je metoda koju Spring koristi za load-anje usera iz baze podataka
//username ce imati onu vrijednost koju ce upisati korisnika
//return vraca Spring Security Usera i radi se usporedba passworda i ostalog (moramo vratiti usera koji je dosao iz UserDetailsService)

//AppUser user = userRepo.findByUsername(username);
//prvo loadamo usera na temelju imena kojeg je korisnik upisao
//"user" sadrzi usera kojeg smo nasli u bazi podataka

//.getRoles() 
//kada dohvati sve role, loopa po svakoj roli od tog korisnika i za svaku kreira SimpleGrandtedAuthority tako da saljemo ime te role i zatim ju dodajemo u listu

//kada misem predes preko "User" vidis sto je potrebno kao treci parametar i vidimo da authorities moze biti kolekcija bilo kojeg tupa koja nasljeđuje SimpleGrandtedAuthority

//TUTORIAL
//org.springframework.security.core.userdetails.User(username, username, null);
//pisao je ovako dugacko zato jer ono sto je nama AppUser njemu se zove "User" tj. isto kao i ovo pa je zato upisao puno ime da se razlikuje

package com.example.demo.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.transaction.Transactional;

import org.springframework.context.annotation.Bean;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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
public class AppUserServiceImpl implements AppUserService, UserDetailsService {
	private final AppUserRepo userRepo;
	private final RoleRepo roleRepo;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		AppUser user = userRepo.findByUsername(username);
		if(user == null) {
			log.error("User not found in the database");
			throw new UsernameNotFoundException("User not found in the database");
		} else { //ako username nije null znaci da bi ga trebali moci pronaci u bazi podataka
			log.info("User found in the database: {}", username);
			
		}
		
		Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
		
		user.getRoles().forEach(role -> {
			authorities.add(new SimpleGrantedAuthority(role.getName()));
		});
	
		return new User(user.getUsername(), user.getPassword(), authorities);
	}
	
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
