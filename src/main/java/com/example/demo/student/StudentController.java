package com.example.demo.student;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.models.Student;

@RestController
@RequestMapping(path = "api/v1/student")
public class StudentController {
	
	private final StudentService studentService;
	
	//Constructor
	@Autowired
	public StudentController(StudentService studentService) {
		super();
		this.studentService = studentService;
	}
	
	@Secured({"ROLE_USER","ROLE_MANAGER", "ROLE_ADMIN", "ROLE_SUPER_ADMIN"})
	@GetMapping
	public List<Student> getStudents() {
		return studentService.getStudents();
	}
	
	@Secured({"ROLE_ADMIN", "ROLE_SUPER_ADMIN"})
	@PostMapping
	public void registerNewStudent(@RequestBody Student student) {
		studentService.addNewStudent(student);
	}
	
	@Secured({"ROLE_SUPER_ADMIN"})
	@DeleteMapping(path = "{studentId}")
	public void deleteStudent(@PathVariable("studentId") Long studentId) {
		studentService.deleteStudent(studentId);
	}
	
	@Secured({"ROLE_MANAGER", "ROLE_ADMIN", "ROLE_SUPER_ADMIN"})
	@PutMapping(path = "{studentId}")
	public void updateStudent(
		@PathVariable("studentId") Long studentId,
		@RequestParam(required = false) String name,
		@RequestParam(required = false) String email) {
		studentService.updateStudent(studentId, name, email);
	}
}	
