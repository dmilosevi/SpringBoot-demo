package com.example.demo.student;

import java.time.LocalDate;
import java.time.Month;
import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.example.demo.models.AppUser;
import com.example.demo.models.Role;
import com.example.demo.models.Student;
import com.example.demo.service.AppUserService;

@Configuration
public class StudentConfig {

	@Bean
	CommandLineRunner commandLineRunner(StudentRepository studentRepository, AppUserService userService) {
		return args -> {
			Student dominik = new Student(
				1L,
				"Dominik",
				"domiloevi@gmail.com",
				LocalDate.of(1998, Month.NOVEMBER, 30)
			);
			
			Student ana = new Student(
				2L,
				"Ana",
				"anahorvat1611@gmail.com",
				LocalDate.of(2000, Month.NOVEMBER, 16)
			);
			
			studentRepository.saveAll(
				List.of(dominik, ana)
			);
			
			//JPA ce napraviti ID za nas
			userService.saveRole(new Role(1L, "ROLE_USER"));
			userService.saveRole(new Role(2L, "ROLE_MANAGER"));
			userService.saveRole(new Role(3L, "ROLE_ADMIN"));
			userService.saveRole(new Role(4L, "ROLE_SUPER_ADMIN"));
			
			userService.saveUser(new AppUser(5L, "John Travolta", "john", "john123", new ArrayList<>()));
			userService.saveUser(new AppUser(6L, "Will Smith", "will", "will123", new ArrayList<>()));
			userService.saveUser(new AppUser(7L, "Jim Carry", "jim", "jim123", new ArrayList<>()));
			userService.saveUser(new AppUser(8L, "Arnold Schwarzenegger", "arnold", "arnold123", new ArrayList<>()));
			
			userService.addRoleToUser("john", "ROLE_USER");
			userService.addRoleToUser("john", "ROLE_MANAGER");
			userService.addRoleToUser("will", "ROLE_MANAGER");
			userService.addRoleToUser("jim", "ROLE_ADMIN");
			userService.addRoleToUser("arnold", "ROLE_SUPER_ADMIN");
			userService.addRoleToUser("arnold", "ROLE_ADMIN");
			userService.addRoleToUser("arnold", "ROLE_USER");
		};
	}
}
