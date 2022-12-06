//WebSecurityConfigurerAdapter
//klasa koju cemo naslijediti kako bi override-ali odredene metode i rekli Springu na koji nacin zelimo upravljati userima i security-em u applikaciji
//NO U OVOJ VERZIJI SPRING BOOTA SE NE MOZE KORISTITI JER JE ZASTARJELA

package com.example.demo.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter{@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// TODO Auto-generated method stub
		super.configure(auth);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// TODO Auto-generated method stub
		super.configure(http);
	}
	
	//postoji vise nacina na koje mozemo reci Springu na koji nacin da trazi korisnike
	//inMemoryAuthentication (proslijedujemo username i password kako bi Spring napravio provjeru kada god user pokusava napraviti prijavu u aplikaciju)
	//jdbcAuthentication(kreirao service klasu i proslijedujemo querye, zatim koristimo JDBC da napravimo vlastiti request
	//userDetailsService

}
