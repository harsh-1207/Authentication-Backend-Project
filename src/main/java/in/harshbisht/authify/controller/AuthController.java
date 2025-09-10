package in.harshbisht.authify.controller;

import in.harshbisht.authify.io.AuthRequest;
import in.harshbisht.authify.io.AuthResponse;
import in.harshbisht.authify.service.AppUserDetailsService;
import in.harshbisht.authify.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class AuthController {                                                           // Handles login and sends JWT

    private final AuthenticationManager authenticationManager;                          // Validates credentials
    private final AppUserDetailsService appUserDetailsService;
    private final JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        try {
            authenticate(request.getEmail(), request.getPassword());

            // need to send the JWT token, and we're doing that using cookie
            final UserDetails userDetails = appUserDetailsService.loadUserByUsername(request.getEmail());   // Loads user info from the database, which is essential for generating a JWT with claims like roles or authorities.
            final String jwtToken = jwtUtil.generateToken(userDetails);                         // Using a util class to encapsulate token creation, great for separation of concerns.
            ResponseCookie cookie = ResponseCookie.from("jwt", jwtToken)                // This ensures the token is stored in an HTTP-only cookie, which protects it from XSS attacks.
                    .httpOnly(true)
                    .path("/")
                    .maxAge(Duration.ofDays(1))
                    .sameSite("Strict")
                    .build();
            return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
                    .body(new AuthResponse(request.getEmail(), jwtToken));
        } catch (BadCredentialsException ex) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", true);
            error.put("message", "Email or password is incorrect");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        } catch (DisabledException ex) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", true);
            error.put("message", "Account is disabled");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        }catch (Exception ex) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", true);
            error.put("message", "Authentication failed");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        }
    }

    private void authenticate(String email, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));       // This delegates to Spring Security’s AuthenticationManager, which uses your configured DaoAuthenticationProvider to validate credentials.
    }
}
