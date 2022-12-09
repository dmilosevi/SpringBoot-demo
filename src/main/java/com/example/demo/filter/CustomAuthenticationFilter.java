//extendali smo klasu UsernamePasswordAuthenticationFilter i zelimo override-ati dvije metode (attemptAuthentication i successfulAuthentication)
//osim te 2 metode mozemo override-ati i metodu "unsucessfulAuthentication" - npr. u njoj mozes implementirati da se acc usera zakljuca ako se ne uspije prijaviti nakon x puta

//AuthenticationManager nam treba za autentikaciju korisnika (AUTHENTICATION)

//successfulAuthentication
//ova metoda ce biti pozvana kada autentikacija korisnika bude uspjena i moramo poslati access token, refresh token
//unutar ove metode zelimo generirati token, potpisati ga i poslati token useru
//ova metoda kao sto vidis prima i request i response i mozemo koristiti taj response da proslijedimo headers ili nesto u body-u (u nasem slucaju ce to biti token)

//.getPrincipal()
//vraca objekt, a objekt je user koji je uspjesno autenticiran i zato castamo u (User)

//Algorithm
//dolazi iz Library-a kojeg smo ubacili u pom.xml

//HMAC256
//postoje dva HMAC256 (jedan koji prima parametar string a drugi koji prima array byte-ova) i odaberemo koji prima array byte-ova

//.withSubject(user.getUsername())
//unutar zagrada obicno ide ono sto je app unique (u nasem slucaju je to username)

//.withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority)
//daje string i zato nakon toga slijedi .collect()


package com.example.demo.filter;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter { // /login dolazi iz ove extendane klase (/login nije u UserControlleru)
	private final AuthenticationManager authenticationManager;
	
	public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
		String username = request.getParameter("username");
		String password = request.getParameter("password");
		log.info("Username is: {}", username);
		log.info("Password is: {}", password);
		//za sada nismo napravili nista puno, samo smo uzeli informacije (username i password) koji su dosli unutar requesta i napravili objekt "UsernamePasswordAuthenticationToken"
		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
		return authenticationManager.authenticate(authenticationToken); //kazemo auhenticationManager-u da autenticira korisnika koji se prijavio s tim informacijama iz requesta
	}

	//prvo zelimo pristupiti useru koji je autenticiran jer trebamo njegove informacije
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
		//ovo je user koji dolazi iz Spring Security, a ne user koji je definiran u nasoj domeni (AppUser)
		User user = (User)authentication.getPrincipal(); //sada imamo usera koji je uspjesno autenticiran i mozemo pristupiti njegovim informacijama kako bi kerirali token
		Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());//ovo je algoritam kojim cemo potpisivati access i refresh token
		String accessToken = JWT.create()
				.withSubject(user.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000)) //postavili smo da token traje 10 min (*1000 jer je u milisekundama)
				.withIssuer(request.getRequestURL().toString()) //company name ili autor tokena (u nasem slucaju ce to biti URL aplikacije)
				.withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
						//proslijedujemo i sve roles za tog usera - .withClaim() prima ime claim-a i neku listu/sort koja sadrzi sve claim-ove
						//"roles" jer ce to biti ime key-a od roles liste koju imamo
						//.stream() predstavlja sekvencu objekata kako bi nad njima mogli izvoditi operacije (.map())
						//ono sto je u () od .map je funkcija koja ce se primjenjivati nad svakim elementom u .stream() i vratiti ce novi stream
				.sign(algorithm); 
		
		//on ce uvijek imati duze vrijeme
		//ne mora imati "roles" kao accessToken
		String refreshToken = JWT.create()
				.withSubject(user.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000)) //postavili smo da token traje 30 min (*1000 jer je u milisekundama)
				.withIssuer(request.getRequestURL().toString()) //company name ili autor tokena (u nasem slucaju ce to biti URL aplikacije)
				.sign(algorithm); 
		
		//sada kada imamo oba tokena mozemo koristiti response da vratimo tokene useru na frontend i poslat cemo ih u headeru
		//kada se user uspjesno prijavu u header-u response-a ce biti oba access i refresh token
		//umjesto setHeader() zelimo zapravo poslati putem response body-a
		/*response.setHeader("accessToken" , accessToken);
		response.setHeader("refreshToken" , refreshToken);*/
		
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
		
		//ako sada napravimo POST test u Postmanu ispisat ce u "Body" access i refresh token u JSON formatu (nece vise biti u Headers)
	}

}
