//ovo je API LAYER i u njega cemo injectati SERVICE LAYER
//injcetamo na isti nacin na koji smo injectali repozitorije u service tj. DAO LAYER u SERVICE LAYER

//@RequiredArgsConstructor
//Lombok ce kreirati konstruktor i pobrinuti se da su svi argumenti (userService) proslijedeni u kontrusktor
//ovo je zapravo DEPENDENCY INJECTION

//ResponseEntity
//predstavlja HTTP response: status code, headers i body
//po defaultu je generic (ReponseEntity<>) tako da mu moramo proslijediti tip, a nas tip ce biti lista AppUser-a

//.ok() vraca 200 - znaci da je sve proslo uredu
//.created() vraca 201 - znaci da je nesto (nekakav resurs) kreirano na serveru
//.body() - unutar () mora biti nekakav porvatni tip tj. u body-u se nalazi ono sto vracamo i to se nalazi u body-u od response-a

//userService.addRoleToUser(form.getUsername(), form.getRoleName());
//ovo ne moze biti unutar body-a jer nista ne vraca (void) tj. mora unutar bodya biti nesto sto vraca konkretnu vrijednost

//return ResponseEntity.ok().build();
//zelimo samo poslati response tako da napravimo build tog response-a

//URI
//unutar URI.create() moze se nalaziti neki string ali u ovom slucaju zelimo server path
//ServletUriComponentsBuilder.fromCurrentContextPath() ovo ce nam dati localhost8080
//.toUriString() - pretvara sve prije u URI string
//URI ce se nalaziti u jednom od headers

//ResponseEntity<?> - zato jer nista ne vracamo

package com.example.demo.api;

import java.net.URI;
import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.example.demo.models.AppUser;
import com.example.demo.models.Role;
import com.example.demo.service.AppUserService;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class UserController {
	
	private final AppUserService userService;
	
	@GetMapping("/users")
	public ResponseEntity<List<AppUser>> getUsers() {
		return ResponseEntity.ok().body(userService.getUsers());
	}
	
	@PostMapping("/user/save")
	public ResponseEntity<AppUser> saveUser(@RequestBody AppUser user) {
		URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());
		return ResponseEntity.created(uri).body(userService.saveUser(user));
	}
	
	@PostMapping("/role/save")
	public ResponseEntity<Role> saveRole(@RequestBody Role role){
		URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
		return ResponseEntity.created(uri).body(userService.saveRole(role));
	}
	
	@PostMapping("/role/addtouser")
	public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserForm form){
		userService.addRoleToUser(form.getUsername(), form.getRoleName());
		return ResponseEntity.ok().build();
	}
}

@Data
class RoleToUserForm {
	private String username;
	private String roleName;
}
