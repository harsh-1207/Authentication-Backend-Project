package in.harshbisht.authify.config;

import in.harshbisht.authify.filter.JwtRequestFilter;
import in.harshbisht.authify.service.AppUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityDsl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AppUserDetailsService appUserDetailsService;
    private final JwtRequestFilter jwtRequestFilter;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{     // Defines access rules and filter order
        http.cors(Customizer.withDefaults())                    // cors -> cross origin resource sharing, Useful when your frontend is hosted separately
                .csrf(AbstractHttpConfigurer::disable)          // Disables CSRF protection, which is standard for stateless APIs using tokens instead of cookies.
                .authorizeHttpRequests(auth -> auth             // Allows unauthenticated access to login and password recovery endpoints, All other endpoints require a valid JWT.
                        .requestMatchers("/login", "/register", "/send-reset-otp", "/reset-password")
                        .permitAll().anyRequest().authenticated())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))       // Ensures Spring doesn’t create or use HTTP sessions, Perfect for JWT-based authentication.
                .logout(AbstractHttpConfigurer::disable)                                                            // Disables Spring Security’s default logout handling.
                .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class)                      // Injects your custom JWT filter before Spring’s default username/password filter, This is where you extract the token, validate it, and set the authentication context.
                .exceptionHandling(ex -> ex.authenticationEntryPoint(customAuthenticationEntryPoint));              // Specifies a custom handler for unauthenticated access attempts.
        return http.build();
    }

    // BCrypt is a one-way hashing algorithm with built-in salting and adaptive complexity, making it resistant to brute-force attacks.
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // This filter intercepts incoming HTTP requests and applies CORS rules before they reach your controllers.
    // It creates a new CorsFilter using a CorsConfigurationSource, which you must define elsewhere in your config class.
    @Bean
    public CorsFilter corsFilter() {
        return new CorsFilter(corsConfigurationSource());
    }


    private CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();                                     // Creates a new CORS policy object.
        config.setAllowedOrigins(List.of("http://localhost:5173"));                         // port where our react app will be running
        config.setAllowedMethods(List.of("GET", "POST", "DELETE", "PUT", "PATCH", "OPTIONS"));  // Permits all standard HTTP methods, including preflight OPTIONS requests.
        config.setAllowedHeaders(List.of("Authorization", "Content-type"));                     // Specifies which headers the frontend is allowed to send. These are common for JWT-based auth and JSON payloads.
        config.setAllowCredentials(true);                                                       // Allows cookies or authorization headers to be sent with requests. Required if you're using Authorization headers or session cookies.

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);                                // Applies this CORS policy to all endpoints in your backend.
        return source;
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();     // This provider uses your custom UserDetailsService (appUserDetailsService) to load user data from the database.
        authenticationProvider.setUserDetailsService(appUserDetailsService);                    // It compares the raw password (from login) with the encoded password using the PasswordEncoder.
        authenticationProvider.setPasswordEncoder(passwordEncoder());                           // sets the pass encoder from above
        return new ProviderManager(authenticationProvider);        // This wraps your authentication provider into an AuthenticationManager, which Spring Security uses to authenticate login attempts.
    }
}
