package in.harshbisht.authify;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthifyApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthifyApplication.class, args);
	}

}

// this branch only has the functionality till point 13
// this is all before adding email functionality (login and get back JWT token)