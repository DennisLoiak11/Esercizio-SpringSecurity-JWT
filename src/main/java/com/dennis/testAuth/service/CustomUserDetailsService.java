package com.dennis.testAuth.service;

import com.dennis.testAuth.model.User;
import com.dennis.testAuth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService { //UserDetailsService è un’interfaccia di Spring Security che definisce un solo metodo che serve per
    // caricare i dettagli di un utente (username, password, ruoli).

    @Autowired
    private UserRepository userRepository;

    @Override
    //Spring Security usa questo metodo ogni volta che deve autenticare un utente, il parametro username è quello che arriva dalla richiesta di login
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username) //Si cerca l'utente nel Database
                .orElseThrow(() -> new UsernameNotFoundException("Utente non trovato: " + username));

        //Costruzione di un oggetto UserDetails che Spring Security capisce
        return org.springframework.security.core.userdetails.User
                .withUsername(user.getUsername())    // username dell'utente
                .password(user.getPassword())        // password (criptata)
                .roles(user.getRole().name())        // ruoli (es. ADMIN o USER)
                .build();                            // costruiamo l'oggetto finale
    }
}
