package profe.authorization;


import java.util.logging.Logger;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@EnableDiscoveryClient
@RestController
@RequestMapping("/")
public class AuthController {

	protected Logger logger = Logger.getLogger(AuthController.class
			.getName());
	

	public static void main(String[] args) {
		System.setProperty("spring.config.name", "auth-server");
		SpringApplication.run(AuthController.class, args);
	}

	@PostMapping
	public String process() {
		return "Wrong request";
	}
	
	/*
	 * Por aquí parece que no se pasa nunca, investigar por qué
	 */
	@PostMapping("/auth")
	public String authorize() {
		logger.info("Petición de autenticación recibida");
		return "Petición de autenticación recibida";
	}
	
}
