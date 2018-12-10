package profe.authorization.security;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Configuración de seguridad. Aquí especificamos usuarios, contraseñas y roles por una parte,
 * y configuramos la seguridad añadiendo el filtro personalizado de autenticación
 * 
 * @author made
 *
 */
@EnableWebSecurity
@Configuration
public class AuthSecurityConfig extends WebSecurityConfigurerAdapter {

	@Value("${app.jwtSecretKey}")
	private String jwtSecretKey;

	@Value("${app.authUrl}")
	private String authUrl;

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth
			.inMemoryAuthentication()
			.withUser("profe").password("{noop}profe").roles("USER")
				.and()
			.withUser("admin").password("{noop}admin").roles("ADMIN");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable()
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
		    // Add a filter before UsernamePasswordAuthenticationFilter to validate user credentials 
			// and add token in the response header
		    // What's the authenticationManager()? 
		    // An object provided by WebSecurityConfigurerAdapter, used to authenticate the user 
			// passing user's credentials
		    // The filter needs this auth manager to authenticate the user.
		    .addFilterBefore(new AuthenticationFilter(authUrl, jwtSecretKey, authenticationManager()),
                    UsernamePasswordAuthenticationFilter.class)	
			.authorizeRequests()
			    // allow all POST requests 
			    .antMatchers(HttpMethod.POST).permitAll()
			    // any other requests is denied
			    .anyRequest().denyAll();
	}
	
}
