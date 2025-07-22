package com.dennis.testAuth.service;

import com.dennis.testAuth.model.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class JwtService {

    // La chiave segreta per firmare i token JWT
    @Value("${security.jwt.secret}") //@Value permette di leggere il valore della chiave segreta dall'application.yaml
    private String secret;

    // Durata di validità del token (in millisecondi)
    @Value("${security.jwt.expiration}") //@Value permette di leggere il valore della scadenza dall'application.yaml
    private long expiration;

    //Metodo per la generazione del token
    public String generateToken(String username, Role role) {
        return Jwts.builder()
                .setSubject(username) //Specifica l'utente "proprietario" del token tramite username
                .claim("role", role.name()) //Aggiunta del campo extra "role" nel payload del JWT
                .setIssuedAt(new Date()) //Salva la data di creazione del token
                .setExpiration(new Date(System.currentTimeMillis() + expiration)) //Imposta la data di scadenza
                .signWith(SignatureAlgorithm.HS256, secret) //Firma il token con l'algoritmo di cifratura e la chiave segreta
                .compact(); //Costruisce il token e lo restituisce come stringa
    }

    public String extractUsername(String token) {
        return getClaims(token).getSubject(); //Ritorna il subject dai claims presenti nel payload del token
    }

    public String extractRole(String token) {
        return getClaims(token).get("role", String.class); //Legge il ruolo dai claims nel payload del token e lo ritorna come stringa (dato che i claims sono organizzati in una Map<>)
    }

    public boolean isTokenValid(String token) {
        try {
            getClaims(token); //Se il parsing funziona, il token è valido
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false; //Qualsiasi errore significa token non valido
        }
    }

    private Claims getClaims(String token) {
        return Jwts.parser()
                .setSigningKey(secret)  //Controlla che la firma sia corretta usando la chiave segreta (secret)
                .parseClaimsJws(token)  //Analizza il token e controlla che non sia scaduto
                .getBody();             //Restituisce i claims (informazioni relative all’utente contenute nel payload)
    }
}