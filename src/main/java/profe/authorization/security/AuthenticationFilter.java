package profe.authorization.security;


import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.Date;
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
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import profe.empleados.model.LoginUser;

public class AuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	private String jwtSecretKey;

    public AuthenticationFilter(String url, String secretKey, AuthenticationManager authManager) {
        super(new AntPathRequestMatcher(url));
        this.jwtSecretKey = secretKey;
        setAuthenticationManager(authManager);
    }

    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest req, HttpServletResponse res)
            throws AuthenticationException, IOException, ServletException {

        // obtenemos el body de la peticion que asumimos viene en formato JSON
        InputStream body = req.getInputStream();

        // Asumimos que el body tendrá el siguiente JSON  {"username":"ask", "password":"123"}
        // Realizamos un mapeo a nuestra clase User para tener ahi los datos
        LoginUser user = new ObjectMapper().readValue(body, LoginUser.class);

        // Finalmente autenticamos
        // Spring comparará el user/password recibidos
        // contra el que definimos en la clase SecurityConfig
        return getAuthenticationManager().authenticate(
                new UsernamePasswordAuthenticationToken(
                        user.getUserName(),
                        user.getPassword(),
                        Collections.emptyList() // Colección de granted authorities, pero no sé para qué
                )
        );
    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest req,
            HttpServletResponse res, FilterChain chain,
            Authentication auth) throws IOException, ServletException {

        // Como la autenticacion fue exitosa, agregamos el token a la respuesta
		String token = Jwts.builder().setSubject(auth.getName())
				.claim("authorities", auth.getAuthorities().stream()
						.map(GrantedAuthority::getAuthority).collect(Collectors.toList()))	
				// Vamos a asignar un tiempo de expiración de 60 minutos
				.setExpiration(new Date(System.currentTimeMillis() + (1000 * 60 * 60)))

				// Hash con el que firmaremos la clave
				.signWith(SignatureAlgorithm.HS512, jwtSecretKey).compact();

		// agregamos al encabezado el token
		res.addHeader("Authorization", "Bearer " + token);
    }
}