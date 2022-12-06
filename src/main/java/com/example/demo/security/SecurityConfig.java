//@RequiredArgsConstructor
//se uvijek pise kada se koristi DEPENDENCY INJECTION

//postoji vise nacina na koje mozemo reci Springu na koji nacin da trazi korisnike
//inMemoryAuthentication (proslijedujemo username i password kako bi Spring napravio provjeru kada god useri pokusavaju napraviti prijavu u aplikaciju)
//jdbcAuthentication(kreiramo service klasu i proslijedujemo querye, zatim koristimo JDBC da napravimo vlastiti request
//userDetailsService - cemo koristiti mi

//WebSecurityConfigurerAdapter
//to je glavna klasa za Security
//klasa koju cemo naslijediti kako bi override-ali odredene metode i rekli Springu na koji nacin zelimo upravljati userima i security-em u applikaciji


package com.example.demo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.demo.filter.CustomAuthenticationFilter;


@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	//TUTORIAL
	//ovo su dva Bean-a
	//Spring u svakom slucaju mora znati na koji nacin da trazi korisnike
	//bez obzira sto ovo (dvije private final ispod) predstavlja Bean-ove, moramo u app napraviti 2 bean-a (jedan je na dnu, a drugi je u AppUserServiceImpl
		//PasswordEncoder ne zelimo override-ati nego zelimo koristiti po defaultu iz Springa + stavljamo mu anotaciju @Bean
		//UserDetailsService je Bean koji moramo override-ati (kako bi Sping znao na koji nacin da trazi korisnike) tako da implementiramo (implements)
		//UserDetailsSerice unutar AppUserServiceImpl i zatim override-amo tu jednu metodu kako bi Spring znao kako load-ati usere i zatim provjeriti username, 
	   //password i ostalo
	
	
	//private final BCryptPasswordEncoder bCryptPasswordEncoder; - ovo je Bean za password encoding koji mozemo override-ati i napraviti svoj vlastiti password encoder 
																//ili ga koristiti takav kakav je
	//private final UserDetailsService userDetailsService;
	
	//RAZLIKA izmedu TUTORIAL-a i ovog koda je sto on ima ova dva Bean-2 iznad + @Bean za PasswordEncoder unutar DemoApplication i Override metode loadUserByUsername
	//unutar AppUserServiceImpl sto zapravo predstavlja UserDetailsSerice Bean
	//njemu se @Bean za PasswordEncoder nalazi u DemoApplication no mi smo ga stavili na dno jer nam nije radio
	
	
	private final UserDetailsService userDetailsService; 
	
	public SecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		//.userDetailsService() ce primati userDetailsService koji je Bean koji moramo override-ati kako bi Spring znao na koji nacin da trazi korisnike
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
		super.configure(auth);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		http.authorizeRequests().anyRequest().permitAll();
		http.addFilter(new CustomAuthenticationFilter(authenticationManagerBean()));
	}
	
	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
	    return new BCryptPasswordEncoder();
	}
	
}

