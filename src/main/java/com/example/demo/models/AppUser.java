//koristimo AppUser kako bi ga mogli razlikovati od Spring Security Usera
//svaki korisnik ce imati ID, name, username, password i listu permisija (roles)

//@ManyToMany
//moramo definirati fetch jer kada fetchamo sve usere/ili kada ih load-amo zelimo takoder load-ati sve roles
//nema se vremena ucitavati Usera, a da se ne ucita Role
//postavili smo "fetch = FetchType.EAGER" jer zelimo load-ati sve roles kada god loadamo nekog usera tj. loadat cemo usera i u isto vrijeme 
	//sve roles iz baze

//@Data
//anotacija iz Lomboka koja zapravo predstavlja gettere i settere

//@NoArgsConstructor
//anotacija iz Lomboka koja zapravo predtavlja konstruktor bez argumenata

//@AllArgsConstructor
//anotacija iz Lomvoka koja zapravo predstavlja konstruktor sa svim argumetima

//@GeneratedValue(strategy = GenerationType.AUTO)
//definira na koji nacin se ce se ID generirati tj.postavili smo da se generira automatski


package com.example.demo.models;

import java.util.ArrayList;
import java.util.Collection;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToMany;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AppUser {
	@Id 
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;
	private String name;
	private String username;
	private String password;
	@ManyToMany(fetch = FetchType.EAGER)
	private Collection<Role> roles = new ArrayList<>();
}
