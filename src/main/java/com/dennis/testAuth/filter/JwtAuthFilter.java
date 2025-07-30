package com.dennis.testAuth.filter;

import com.dennis.testAuth.service.CustomUserDetailsService;
import com.dennis.testAuth.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//Creazione di un filtro personalizzato di Spring Security
@Component
public class JwtAuthFilter extends OncePerRequestFilter {
    @Autowired
    private JwtService jwtService;
    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 1. Leggiamo l'header Authorization
        String authHeader = request.getHeader("Authorization");

        // Se l'header è nullo o non inizia con "Bearer ", lasciamo passare la richiesta senza autenticare
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 2. Estrarre il token eliminando "Bearer "
        String jwt = authHeader.substring(7);

        // 3. Estrarre lo username dal token (se il token è valido)
        String username = jwtService.extractUsername(jwt);

        // 4. Se lo username non è nullo e non abbiamo ancora un utente autenticato nel contesto
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Carichiamo i dettagli dell'utente dal database
            UserDetails userDetails = this.customUserDetailsService.loadUserByUsername(username);

            // 5. Verifica se il token è ancora valido
            if (jwtService.isTokenValid(jwt)) {
                // Creiamo un oggetto di autenticazione da passare a Spring
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken
                        (userDetails,null, userDetails.getAuthorities());// ruoli (ROLE_USER, ROLE_ADMIN)

                // Aggiungiamo informazioni sulla richiesta
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Impostiamo l'utente come autenticato nel contesto di sicurezza di Spring
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // 6. Continua la catena di filtri
        filterChain.doFilter(request, response);
    }
}