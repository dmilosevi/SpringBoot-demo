//u CustomAuthenticationFilter smo napravili da user dobije access i refresh token kada se uspije uspjesno ulogirati (postman)
//sada zelimo da user pomocu tih tokena ima pristup aplikaciji tj. da se token verificira (tj. da se provjeri da je valid) i zatim im da pristup aplikaciji
//CustomAuthorizationFilter ce presijecati svaki request koji dolazi prema app, pogledati token i odluciti ima li user pristup trazenim resursima ili ne

package com.example.demo.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

import static java.util.Arrays.stream;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

	//ovu metodu je obavezno override-ati (desni klik -> Source -> Override/Implement Methods...)
	//sva logika koju smo napisali u komentarim gore ce u ovoj metodi biti implementirana	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException{
		//ako je ovakav path onda ne moras napraviti nista jer se user pokusava prijaviti
		if (request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/token/refresh")) {
			filterChain.doFilter(request, response); //ovo ne radi nista obzirom da se user pokusava prijaviti tj. ovo znaci da ce ovaj request otici na
										//drugi filter i filterChain odnosno "pustili" smo request dalje
		} else {
			//.getHeder() sadrzi ime key-a koji trazimo
			String authorizationHeader = request.getHeader("Authorization"); //prvo pokusavamo pristupiti authorization header-u koji bi trebao biti key za token
			//kada god cemo s frontenda slati requets prema backendu slati cemo token nakon sto se uspjesno autenticiramo tj.
			//prvo posaljemo request, ulogiramo se uspjeno, dobijemo token i prilikom slanaj iduceg requesta saljemo token
			//svaki put kada cemo slati request s tokenom stavit cemo "Bearer " i zatim token
			//tko god posalje request, posalje token, i kada se ustanovi da je token validan useru se daju sve permisije i sve sto ide s tokenom
			//provjerava se jel authorizationHeader krece sa "Bearer " jer je to onda znak da se radi o tokenu
			if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
				try {
					String token = authorizationHeader.substring("Bearer ".length()); //.siubstring() prima broj lettersa koji zeliumo ukloniti
					Algorithm algorithm = Algorithm.HMAC256("secret".getBytes()); //ovaj isti algoritam smo koristi za potpisivanje tokena, sada koristimo za verifikaciju tokena
					JWTVerifier verifier = JWT.require(algorithm).build();
					DecodedJWT decodedJWT = verifier.verify(token);
					//sada kada smo verificirali da je token validan mozemo uzeti usera
					String username = decodedJWT.getSubject(); //ovo ce nam dati username koji dolazi s tokenom
					//.getClaim() ce dohvatiti cijelu collection i moramo reci koja vrsta kolekcije je to tj. kako zelimo collectati
					String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
					
					//ne treba nam password usera jer je u ovoj fazi user vec autenticiran i njegov JWT je validan
					
					//razlog zasto radimo ovu konverziju u SimpleGrantedAuthority jer ih moramo convertati u nesto sto nasljeđuje GrantedAuthority, a SimpleGrantedAuthority
					//nasljeđuje GrantedAuthority (SpringBoot ocekuje nesto sto nasljeduje GrantedAuthority)
					Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
					//importali smo rucno stream kao static metodu
					//zelimo strimati kroz sve "roles"
					//za svaki role unutar "roles" zelimo napraviti ovo sto je u {}
					stream(roles).forEach(role -> {
						authorities.add(new SimpleGrantedAuthority(role));
					});
					//null jer password nemamo u ovom trenutku i nije ga potrebno poslati kao parametar
					UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
					//ovo je nacin na koji kazemo Spring Security-u: ovo je user, ovo je njegov username, tu su nejgove roles, i tu je ono sto on moze raditi po aplikaciji
					//Spring ce pogledau usera, nejgove role i odluciti cemu moze pristupiti u aplikaciji
					SecurityContextHolder.getContext().setAuthentication(authenticationToken);
					//i dalje "pustamo" request dalje
					filterChain.doFilter(request, response);
				}//sada zelimo hendlati sve errore koji se mogu dogoditi (token nije validan, nismo ga mogli verificirati, istekao je,..
				//moramo nekako informirati usera sto se dogodilo
				catch (Exception exception) {
					log.error("Error logging in: {}", exception.getMessage());
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
				filterChain.doFilter(request, response);
			}
		}
		
	}

}
