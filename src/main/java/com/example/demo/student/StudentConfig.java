package com.example.demo.student;

import java.time.LocalDate;
import java.time.Month;
import java.util.List;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class StudentConfig {

	@Bean
	CommandLineRunner commandLineRunner(StudentRepository studentRepository) {
		return args -> {
			Student dominik = new Student(
				"Dominik",
				"domiloevi@gmail.com",
				LocalDate.of(1998, Month.NOVEMBER, 30)
			);
			
			Student ana = new Student(
				"Ana",
				"anahorvat1611@gmail.com",
				LocalDate.of(2000, Month.NOVEMBER, 16)
			);
			
			studentRepository.saveAll(
				List.of(dominik, ana)
			);
		};
	}
}
