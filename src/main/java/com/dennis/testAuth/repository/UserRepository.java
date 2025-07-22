package com.dennis.testAuth.repository;

import com.dennis.testAuth.model.User;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface UserRepository extends MongoRepository<String, User> {
    Optional<User> findByUsername(String username);
}
