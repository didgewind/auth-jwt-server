package profe.authorization.security;

import java.util.Date;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JwtUtil {

	// @Value("${app.jwtSecretKey}")
	private static String jwtSecretKey = "P@tit0";

	// Método para crear el JWT y enviarlo al cliente en el header de la respuesta
	static void addAuthentication(HttpServletResponse res, String username) {

		String token = Jwts.builder().setSubject(username)
						
				// Vamos a asignar un tiempo de expiracion de 60 minutos
				.setExpiration(new Date(System.currentTimeMillis() + (1000 * 60 * 60)))

				// Hash con el que firmaremos la clave
				.signWith(SignatureAlgorithm.HS512, jwtSecretKey).compact();

		// agregamos al encabezado el token
		res.addHeader("Authorization", "Bearer " + token);
	}

}