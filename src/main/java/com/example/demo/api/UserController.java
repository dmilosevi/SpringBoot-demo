//ovo je API LAYER i u njega cemo injectati SERVICE LAYER
//injcetamo na isti nacin na koji smo injectali repozitorije u service tj. DAO LAYER u SERVICE LAYER

//@RequiredArgsConstructor
//Lombok ce kreirati konstruktor i pobrinuti se da su svi argumenti (userService) proslijedeni u kontrusktor
//koristi se za DEPENDENCY INJECTION

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


import java.io.IOException;
import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.example.demo.models.AppUser;
import com.example.demo.models.Role;
import com.example.demo.service.AppUserService;
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class UserController {
	
	private final AppUserService userService;
	
	@Secured({"ROLE_USER","ROLE_MANAGER", "ROLE_ADMIN", "ROLE_SUPER_ADMIN"})
	@GetMapping("/users")
	public ResponseEntity<List<AppUser>> getUsers() {
		return ResponseEntity.ok().body(userService.getUsers());
	}
	
	@Secured({"ROLE_MANAGER", "ROLE_ADMIN", "ROLE_SUPER_ADMIN"})
	@PostMapping("/user/save")
	public ResponseEntity<AppUser> saveUser(@RequestBody AppUser user) {
		URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());
		return ResponseEntity.created(uri).body(userService.saveUser(user));
	}
	
	@Secured({"ROLE_ADMIN", "ROLE_SUPER_ADMIN"})
	@PostMapping("/role/save")
	public ResponseEntity<Role> saveRole(@RequestBody Role role){
		URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
		return ResponseEntity.created(uri).body(userService.saveRole(role));
	}
	
	@Secured({"ROLE_SUPER_ADMIN"})
	@PostMapping("/role/addtouser")
	public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserForm form){
		userService.addRoleToUser(form.getUsername(), form.getRoleName());
		return ResponseEntity.ok().build();
	}
	
	//napravit cemo novi endpoint na koji user moze poslati request u svrhu renew tokena, koji ce onda poslat
	//refresh token, validirat cemo ga i dati useru novi access token
	//injectali smo request i response tako da im imamo pristup
	@GetMapping("/token/refresh")
	public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws JsonGenerationException, JsonMappingException, IOException{
		String authorizationHeader = request.getHeader("Authorization");
		if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
			try {
				String refreshToken = authorizationHeader.substring("Bearer ".length()); //.siubstring() prima broj lettersa koji zeliumo ukloniti
				Algorithm algorithm = Algorithm.HMAC256("secret".getBytes()); //ovaj isti algoritam smo koristi za potpisivanje tokena, sada koristimo za verifikaciju tokena
				JWTVerifier verifier = JWT.require(algorithm).build();
				DecodedJWT decodedJWT = verifier.verify(refreshToken);
				//sada kada smo verificirali da je token validan mozemo uzeti usera
				String username = decodedJWT.getSubject(); //ovo ce nam dati username koji dolazi s tokenom
				//kada dodemo do username-a zelimo loadati usera (zelimo ga pronaci u bazi kako bi bili sigurni da postoji user)
				AppUser user = userService.getUser(username);
				String accessToken = JWT.create()
						.withSubject(user.getUsername())
						.withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000)) //postavili smo da token traje 10 min (*1000 jer je u milisekundama)
						.withIssuer(request.getRequestURL().toString()) //company name ili autor tokena (u nasem slucaju ce to biti URL aplikacije)
						.withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
								//proslijedujemo i sve roles za tog usera - .withClaim() prima ime claim-a i neku listu/sort koja sadrzi sve claim-ove
								//"roles" jer ce to biti ime key-a od roles liste koju imamo
								//.stream() predstavlja sekvencu objekata kako bi nad njima mogli izvoditi operacije (.map())
								//ono sto je u () od .map je funkcija koja ce se primjenjivati nad svakim elementom u .stream() i vratiti ce novi stream
						.sign(algorithm); 
				//Map<> kolekcija koja sadrzi parove objekata (kljuc i vrijednost)
				//Map<K, V> - K predtsvlja kojeg ce tipa biti kljucevi u mapi, V predtavlja kojeg ce tipa biti vrijednosti u mapi
				Map<String, String> tokens = new HashMap<>();
				tokens.put("accessToken" , accessToken);
				tokens.put("refreshToken" , refreshToken);
				
				//postavljamo content type na response (zelimo da bude tipa JSON)
				//ObjectMapper provides functionality for reading and writing JSON, either to and from basic POJOs (Plain Old Java Objects), 
				//or to and from a general-purpose JSON Tree Model ( JsonNode )
				//sada ce se tokeni (access i refresh) prikazati u body-u response-a
				response.setContentType("application/json");
				new ObjectMapper().writeValue(response.getOutputStream(), tokens);
			}//sada zelimo hendlati sve errore koji se mogu dogoditi (token nije validan, nismo ga mogli verificirati, istekao je,..
			//moramo nekako informirati usera sto se dogodilo
			catch (Exception exception) {
				response.setHeader("Error", exception.getMessage());
				response.setStatus(403); //postavljamo status
				//response.sendError(403);
				Map<String, String> error = new HashMap<>();
				//svaki error koji dobijemo cemo ovako hendlati
				error.put("error_message" , exception.getMessage());
				response.setContentType("application/json");
				new ObjectMapper().writeValue(response.getOutputStream(), error);
				
				//sada moramo dodati taj filter u nas SecurityConfig
			}
		} else { 
			throw new RuntimeException("Refresh token is missing");
		}
	}
}

@Data
class RoleToUserForm {
	private String username;
	private String roleName;
}
