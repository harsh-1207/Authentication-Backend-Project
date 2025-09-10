package in.harshbisht.authify.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

//global exception handler class
// used in the securityFilterChain
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {       // Handles unauthorized access
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);            // Sends back a 401 Unauthorized status code.
        response.setContentType("application/json");        // Returns a JSON response instead of redirecting to a login page (which is default behavior in form-based login).
        response.getWriter().write("{\"authenticated\": false, \"message\": \"User is not authenticated\"}");
    }
}
